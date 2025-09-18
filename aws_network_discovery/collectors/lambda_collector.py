"""
Lambda Function Collector
Collects Lambda functions and their VPC configurations
"""

import logging
from typing import Dict, List, Any, Optional

from .base_collector import BaseCollector


logger = logging.getLogger(__name__)


class LambdaCollector(BaseCollector):
    """Collector for Lambda functions"""
    
    def get_resource_type(self) -> str:
        return 'lambda_functions'
    
    def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collect Lambda functions from specified regions
        
        Args:
            regions: List of AWS regions
            account_ids: Optional list of account IDs
            
        Returns:
            Dictionary containing Lambda function data by region
        """
        logger.info(f"Collecting Lambda functions from {len(regions)} regions")
        
        def collect_region_functions(region: str) -> List[Dict[str, Any]]:
            return self._collect_functions_from_region(region)
        
        results = self._collect_parallel(regions, collect_region_functions, "Collecting Lambda functions")
        
        # Store collected data
        self.collected_data = results
        
        # Calculate totals
        total_functions = sum(len(functions) for functions in results.values())
        logger.info(f"Collected {total_functions} Lambda functions across {len(regions)} regions")
        
        return results
    
    def _collect_functions_from_region(self, region: str) -> List[Dict[str, Any]]:
        """
        Collect Lambda functions from a specific region
        
        Args:
            region: AWS region name
            
        Returns:
            List of Lambda function data
        """
        try:
            lambda_client = self._get_client('lambda', region)
            
            # Get current account ID
            sts_client = self._get_client('sts', region)
            account_id = sts_client.get_caller_identity()['Account']
            
            # Collect functions using pagination
            functions = self._retry_operation(
                lambda: self._paginate_results(lambda_client, 'list_functions')
            )
            
            # Enrich each function with detailed configuration
            enriched_functions = []
            for function in functions:
                try:
                    # Get detailed function configuration
                    detailed_config = self._retry_operation(
                        lambda: lambda_client.get_function_configuration(
                            FunctionName=function['FunctionName']
                        )
                    )
                    
                    # Enrich with network information
                    enriched_function = self._enrich_function_data(detailed_config, region, account_id)
                    enriched_functions.append(enriched_function)
                    
                except Exception as e:
                    logger.warning(f"Failed to get detailed config for function {function['FunctionName']}: {e}")
                    # Use basic function data if detailed config fails
                    enriched_function = self._enrich_function_data(function, region, account_id)
                    enriched_functions.append(enriched_function)
            
            # Filter based on configuration
            filtered_functions = self._filter_resources(enriched_functions)
            
            logger.debug(f"Collected {len(filtered_functions)} Lambda functions from region {region}")
            return filtered_functions
            
        except Exception as e:
            logger.error(f"Failed to collect Lambda functions from region {region}: {e}")
            return []
    
    def _enrich_function_data(self, function: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """
        Enrich function data with network-specific information
        
        Args:
            function: Raw Lambda function data
            region: AWS region
            account_id: AWS account ID
            
        Returns:
            Enriched function data
        """
        # Start with base enrichment
        enriched = self._enrich_resource_data(function, region, account_id)
        
        # Extract VPC configuration
        vpc_config = function.get('VpcConfig', {})
        
        # Extract network-specific information
        network_info = {
            'FunctionName': function.get('FunctionName'),
            'FunctionArn': function.get('FunctionArn'),
            'Arn': function.get('FunctionArn'),
            'Runtime': function.get('Runtime'),
            'Role': function.get('Role'),
            'Handler': function.get('Handler'),
            'CodeSize': function.get('CodeSize'),
            'Description': function.get('Description'),
            'Timeout': function.get('Timeout'),
            'MemorySize': function.get('MemorySize'),
            'LastModified': function.get('LastModified'),
            'State': function.get('State'),
            'StateReason': function.get('StateReason'),
            'PackageType': function.get('PackageType'),
            'Architectures': function.get('Architectures', []),
            
            # VPC Configuration
            'VpcConfig': {
                'SubnetIds': vpc_config.get('SubnetIds', []),
                'SecurityGroupIds': vpc_config.get('SecurityGroupIds', []),
                'VpcId': vpc_config.get('VpcId'),
            },
            'HasVpcConfig': bool(vpc_config.get('SubnetIds')),
            
            # Environment variables (may contain network-related config)
            'Environment': function.get('Environment', {}),
            
            # Dead letter queue configuration
            'DeadLetterConfig': function.get('DeadLetterConfig', {}),
            
            # Tracing configuration
            'TracingConfig': function.get('TracingConfig', {}),
            
            # Layers
            'Layers': function.get('Layers', []),
        }
        
        # Extract tags if available
        try:
            lambda_client = self._get_client('lambda', region)
            tags_response = lambda_client.list_tags(Resource=function['FunctionArn'])
            network_info['Tags'] = tags_response.get('Tags', {})
        except Exception as e:
            logger.debug(f"Could not retrieve tags for function {function['FunctionName']}: {e}")
            network_info['Tags'] = {}
        
        # Merge network info with enriched data
        enriched.update(network_info)
        
        return enriched
    
    def get_vpc_functions(self) -> List[Dict[str, Any]]:
        """
        Get Lambda functions that are configured with VPC
        
        Returns:
            List of Lambda functions with VPC configuration
        """
        vpc_functions = []
        for region_functions in self.collected_data.values():
            for function in region_functions:
                if function.get('HasVpcConfig'):
                    vpc_functions.append(function)
        
        return vpc_functions
    
    def get_functions_by_vpc(self, vpc_id: str) -> List[Dict[str, Any]]:
        """
        Get Lambda functions filtered by VPC ID
        
        Args:
            vpc_id: VPC ID to filter by
            
        Returns:
            List of Lambda functions in the specified VPC
        """
        functions = []
        for region_functions in self.collected_data.values():
            for function in region_functions:
                if function.get('VpcConfig', {}).get('VpcId') == vpc_id:
                    functions.append(function)
        
        return functions
    
    def get_functions_by_security_group(self, security_group_id: str) -> List[Dict[str, Any]]:
        """
        Get Lambda functions filtered by security group ID
        
        Args:
            security_group_id: Security group ID to filter by
            
        Returns:
            List of Lambda functions using the specified security group
        """
        functions = []
        for region_functions in self.collected_data.values():
            for function in region_functions:
                sg_ids = function.get('VpcConfig', {}).get('SecurityGroupIds', [])
                if security_group_id in sg_ids:
                    functions.append(function)
        
        return functions
    
    def get_functions_by_subnet(self, subnet_id: str) -> List[Dict[str, Any]]:
        """
        Get Lambda functions filtered by subnet ID
        
        Args:
            subnet_id: Subnet ID to filter by
            
        Returns:
            List of Lambda functions in the specified subnet
        """
        functions = []
        for region_functions in self.collected_data.values():
            for function in region_functions:
                subnet_ids = function.get('VpcConfig', {}).get('SubnetIds', [])
                if subnet_id in subnet_ids:
                    functions.append(function)
        
        return functions
