"""
Base collector class for AWS resources
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError, BotoCoreError
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from aws_network_discovery.auth.sso_auth import SSOAuthenticator
from aws_network_discovery.config.settings import Config


logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Base class for all AWS resource collectors"""
    
    def __init__(self, authenticator: SSOAuthenticator, config: Config):
        """
        Initialize base collector
        
        Args:
            authenticator: AWS SSO authenticator instance
            config: Configuration object
        """
        self.authenticator = authenticator
        self.config = config
        self.collected_data = {}
        self.collected_errors = []  # list of {'phase': str, 'profile': str, 'region': str, 'error': str}
        
    @abstractmethod
    def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collect resources from specified regions and accounts
        
        Args:
            regions: List of AWS regions
            account_ids: Optional list of account IDs
            
        Returns:
            Dictionary containing collected resource data
        """
        pass
    
    @abstractmethod
    def get_resource_type(self) -> str:
        """
        Get the resource type name for this collector
        
        Returns:
            Resource type string (e.g., 'ec2_instances', 'security_groups')
        """
        pass
    
    def _get_client(self, service_name: str, region: str, account_id: Optional[str] = None):
        """
        Get AWS service client for specific region and account
        
        Args:
            service_name: AWS service name
            region: AWS region
            account_id: Optional account ID for cross-account access
            
        Returns:
            AWS service client
        """
        if account_id:
            # For cross-account access, you would typically assume a role
            # This is simplified for now
            pass
        
        return self.authenticator.get_client(service_name, region)
    
    def _paginate_results(self, client, operation_name: str, **kwargs) -> List[Dict[str, Any]]:
        """
        Paginate through AWS API results
        
        Args:
            client: AWS service client
            operation_name: API operation name
            **kwargs: Additional arguments for the operation
            
        Returns:
            List of all results from paginated API calls
        """
        results = []
        
        try:
            paginator = client.get_paginator(operation_name)
            
            for page in paginator.paginate(**kwargs):
                # Extract the main result key (varies by service)
                for key, value in page.items():
                    if isinstance(value, list) and key != 'ResponseMetadata':
                        results.extend(value)
                        break
                        
        except ClientError as e:
            logger.error(f"Error paginating {operation_name}: {e}")
            raise
        
        return results
    
    def _retry_operation(self, operation, max_retries: int = None, delay: float = None) -> Any:
        """
        Retry operation with exponential backoff
        
        Args:
            operation: Function to retry
            max_retries: Maximum number of retries
            delay: Initial delay between retries
            
        Returns:
            Operation result
        """
        max_retries = max_retries or self.config.discovery.max_retries
        delay = delay or self.config.discovery.retry_delay
        
        for attempt in range(max_retries + 1):
            try:
                return operation()
            except (ClientError, BotoCoreError) as e:
                if attempt == max_retries:
                    logger.error(f"Operation failed after {max_retries} retries: {e}")
                    raise
                
                # Check if error is retryable
                if hasattr(e, 'response') and e.response.get('Error', {}).get('Code') in [
                    'Throttling', 'ThrottlingException', 'RequestLimitExceeded'
                ]:
                    wait_time = delay * (2 ** attempt)
                    logger.warning(f"Throttling detected, waiting {wait_time}s before retry {attempt + 1}")
                    time.sleep(wait_time)
                else:
                    # Non-retryable error
                    raise
    
    def _collect_parallel(self, regions: List[str], collect_func, description: str = None) -> Dict[str, Any]:
        """
        Collect resources in parallel across regions
        
        Args:
            regions: List of regions to collect from
            collect_func: Function to collect resources from a single region
            description: Description for progress bar
            
        Returns:
            Dictionary with region as key and collected data as value
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.config.discovery.parallel_workers) as executor:
            # Submit tasks for each region
            future_to_region = {
                executor.submit(collect_func, region): region 
                for region in regions
            }
            
            # Collect results with progress bar
            desc = description or f"Collecting {self.get_resource_type()}"
            for future in tqdm(as_completed(future_to_region), 
                             total=len(regions), 
                             desc=desc):
                region = future_to_region[future]
                try:
                    results[region] = future.result()
                except Exception as e:
                    logger.error(f"Failed to collect from region {region}: {e}")
                    results[region] = []
                    # Record structured error for reporting
                    try:
                        profile = getattr(self.authenticator, 'profile_name', None)
                    except Exception:
                        profile = None
                    self.collected_errors.append({
                        'phase': self.get_resource_type(),
                        'profile': profile,
                        'region': region,
                        'error': str(e),
                    })
        
        return results
    
    def _enrich_resource_data(self, resource: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """
        Enrich resource data with common metadata
        
        Args:
            resource: Raw resource data
            region: AWS region
            account_id: AWS account ID
            
        Returns:
            Enriched resource data
        """
        enriched = resource.copy()
        enriched.update({
            'Region': region,
            'AccountId': account_id,
            'CollectedAt': time.time(),
            'ResourceType': self.get_resource_type(),
            'Profile': getattr(self.authenticator, 'profile_name', None)
        })
        
        return enriched
    
    def _filter_resources(self, resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter resources based on configuration
        
        Args:
            resources: List of resources to filter
            
        Returns:
            Filtered list of resources
        """
        filtered = []
        
        for resource in resources:
            # Skip terminated instances if configured (handle dict or string state)
            if not self.config.discovery.include_terminated_instances:
                state_val = resource.get('State')
                state_name = None
                if isinstance(state_val, dict):
                    state_name = state_val.get('Name')
                elif isinstance(state_val, str):
                    state_name = state_val
                if state_name == 'terminated':
                    continue
            
            # Skip deleted resources if configured
            if (not self.config.discovery.include_deleted_resources and 
                resource.get('Status') == 'deleted'):
                continue
            
            filtered.append(resource)
        
        return filtered
    
    def get_collected_data(self) -> Dict[str, Any]:
        """
        Get collected data
        
        Returns:
            Dictionary containing all collected data
        """
        return self.collected_data

    def get_errors(self) -> List[Dict[str, Any]]:
        """Return structured errors captured during collection."""
        return list(self.collected_errors)
    
    def clear_collected_data(self) -> None:
        """Clear collected data"""
        self.collected_data = {}
