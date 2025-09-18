"""
Discovery Orchestrator
Coordinates the bottom-up discovery process across all AWS resources
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

from aws_network_discovery.auth.sso_auth import SSOAuthenticator
from aws_network_discovery.config.settings import Config
from aws_network_discovery.collectors.ec2_collector import EC2Collector
from aws_network_discovery.collectors.lambda_collector import LambdaCollector
from aws_network_discovery.collectors.rds_collector import RDSCollector
from aws_network_discovery.collectors.elb_collector import ELBCollector
from aws_network_discovery.collectors.security_groups_collector import SecurityGroupsCollector
from aws_network_discovery.collectors.vpc_collector import VPCCollector


logger = logging.getLogger(__name__)


class DiscoveryOrchestrator:
    """
    Orchestrates the bottom-up discovery process following the strict order:
    1. Application Resources (EC2, Lambda, RDS, etc.)
    2. Security Groups
    3. Subnets & NACLs (part of VPC collector)
    4. VPCs
    5. ENIs
    6. Route Tables
    7. Transit Gateway Attachments
    8. VPC Endpoints
    9. Third-Party Services
    10. Network Firewall Rules
    """
    
    def __init__(self, credentials: Dict[str, str], config: Config, profile_name: Optional[str] = None):
        """
        Initialize discovery orchestrator
        
        Args:
            credentials: AWS credentials dictionary
            config: Configuration object
        """
        self.credentials = credentials
        self.config = config
        self.authenticator = None
        self.profile_name = profile_name
        self.collectors = {}
        self.discovery_metadata = {
            'start_time': None,
            'end_time': None,
            'duration_seconds': None,
            'regions': [],
            'accounts': [],
            'resource_counts': {},
            'errors': [],
        }
        
    def _initialize_authenticator(self, profile_name: str = None) -> None:
        """Initialize authenticator with credentials"""
        # For now, we'll create a mock authenticator that uses the provided credentials
        # In a real implementation, you'd pass the profile name used to get these credentials
        class MockAuthenticator:
            def __init__(self, credentials, profile_name=None):
                self.credentials = credentials
                self.profile_name = profile_name
                
            def get_client(self, service_name: str, region_name: str):
                import boto3
                return boto3.client(
                    service_name,
                    region_name=region_name,
                    aws_access_key_id=self.credentials['AccessKeyId'],
                    aws_secret_access_key=self.credentials['SecretAccessKey'],
                    aws_session_token=self.credentials.get('SessionToken')
                )
        
        effective_profile = profile_name or self.profile_name
        self.authenticator = MockAuthenticator(self.credentials, profile_name=effective_profile)
    
    def discover_all(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Execute complete discovery process following bottom-up approach
        
        Args:
            regions: List of AWS regions to discover
            account_ids: Optional list of account IDs
            
        Returns:
            Complete network discovery data
        """
        logger.info("Starting AWS Network Discovery process")
        logger.info(f"Target regions: {regions}")
        logger.info(f"Target accounts: {account_ids or ['Current account']}")
        
        self.discovery_metadata['start_time'] = time.time()
        self.discovery_metadata['regions'] = regions
        self.discovery_metadata['accounts'] = account_ids or [self.credentials.get('Account')]
        
        # Initialize authenticator
        self._initialize_authenticator()
        
        # Initialize collectors
        self._initialize_collectors()
        
        # Execute discovery in strict bottom-up order
        discovery_data = {}
        
        try:
            # Phase 1: Application Resources Discovery
            logger.info("Phase 1: Discovering Application Resources")
            discovery_data.update(self._discover_application_resources(regions, account_ids))
            
            # Phase 2: Security Groups
            logger.info("Phase 2: Discovering Security Groups")
            discovery_data.update(self._discover_security_groups(regions, account_ids))
            
            # Phase 3: VPC Components (Subnets, NACLs, VPCs, Route Tables, etc.)
            logger.info("Phase 3: Discovering VPC Components")
            discovery_data.update(self._discover_vpc_components(regions, account_ids))
            
            # Phase 4: Network Interfaces (ENIs)
            logger.info("Phase 4: Discovering Network Interfaces")
            discovery_data.update(self._discover_network_interfaces(regions, account_ids))
            
            # Phase 5: Transit Gateway Components
            logger.info("Phase 5: Discovering Transit Gateway Components")
            discovery_data.update(self._discover_transit_gateways(regions, account_ids))
            
            # Phase 6: VPC Endpoints
            logger.info("Phase 6: Discovering VPC Endpoints")
            # VPC Endpoints are already collected in VPC collector
            
            # Phase 7: Third-Party Services
            logger.info("Phase 7: Discovering Third-Party Services")
            discovery_data.update(self._discover_third_party_services(regions, account_ids))
            
            # Phase 8: Network Firewall Rules
            logger.info("Phase 8: Discovering Network Firewall Rules")
            discovery_data.update(self._discover_network_firewalls(regions, account_ids))
            
            # Calculate resource counts
            self._calculate_resource_counts(discovery_data)
            
            # Add metadata
            discovery_data['metadata'] = self._finalize_metadata()
            
            logger.info("AWS Network Discovery completed successfully")
            return discovery_data
            
        except Exception as e:
            logger.error(f"Discovery process failed: {str(e)}")
            self.discovery_metadata['errors'].append(str(e))
            raise
    
    def _initialize_collectors(self) -> None:
        """Initialize all resource collectors"""
        self.collectors = {
            'ec2': EC2Collector(self.authenticator, self.config),
            'lambda': LambdaCollector(self.authenticator, self.config),
            'rds': RDSCollector(self.authenticator, self.config),
            'elb': ELBCollector(self.authenticator, self.config),
            'security_groups': SecurityGroupsCollector(self.authenticator, self.config),
            'vpc': VPCCollector(self.authenticator, self.config),
        }
    
    def _discover_application_resources(self, regions: List[str], account_ids: Optional[List[str]]) -> Dict[str, Any]:
        """Discover application resources (EC2, Lambda, RDS, etc.)"""
        app_resources = {}
        
        # EC2 Instances
        logger.info("Collecting EC2 instances...")
        ec2_data = self.collectors['ec2'].collect(regions, account_ids)
        app_resources['ec2_instances'] = ec2_data
        
        # Lambda Functions
        logger.info("Collecting Lambda functions...")
        lambda_data = self.collectors['lambda'].collect(regions, account_ids)
        app_resources['lambda_functions'] = lambda_data
        
        # RDS Instances
        logger.info("Collecting RDS instances...")
        rds_data = self.collectors['rds'].collect(regions, account_ids)
        app_resources['rds_instances'] = rds_data
        
        # Load Balancers (ALB/NLB)
        logger.info("Collecting Load Balancers...")
        elb_data = self.collectors['elb'].collect(regions, account_ids)
        app_resources['load_balancers'] = elb_data
        
        return app_resources
    
    def _discover_security_groups(self, regions: List[str], account_ids: Optional[List[str]]) -> Dict[str, Any]:
        """Discover security groups and their rules"""
        logger.info("Collecting Security Groups...")
        sg_data = self.collectors['security_groups'].collect(regions, account_ids)
        return {'security_groups': sg_data}
    
    def _discover_vpc_components(self, regions: List[str], account_ids: Optional[List[str]]) -> Dict[str, Any]:
        """Discover VPC components (VPCs, Subnets, Route Tables, NACLs, etc.)"""
        logger.info("Collecting VPC components...")
        vpc_data = self.collectors['vpc'].collect(regions, account_ids)
        return {'vpc_components': vpc_data}
    
    def _discover_network_interfaces(self, regions: List[str], account_ids: Optional[List[str]]) -> Dict[str, Any]:
        """Discover Elastic Network Interfaces (ENIs)"""
        # This would be implemented as a separate collector
        # For now, return placeholder
        return {'network_interfaces': {region: [] for region in regions}}
    
    def _discover_transit_gateways(self, regions: List[str], account_ids: Optional[List[str]]) -> Dict[str, Any]:
        """Discover Transit Gateways and their attachments"""
        # This would be implemented as a separate collector
        # For now, return placeholder
        return {'transit_gateways': {region: [] for region in regions}}
    
    def _discover_third_party_services(self, regions: List[str], account_ids: Optional[List[str]]) -> Dict[str, Any]:
        """Discover third-party service connections (MongoDB Atlas, Databricks, etc.)"""
        third_party = {}
        
        if self.config.discovery.mongodb_atlas_enabled:
            third_party['mongodb_atlas'] = self._discover_mongodb_atlas(regions)
        
        if self.config.discovery.databricks_enabled:
            third_party['databricks'] = self._discover_databricks(regions)
        
        return {'third_party_services': third_party}
    
    def _discover_network_firewalls(self, regions: List[str], account_ids: Optional[List[str]]) -> Dict[str, Any]:
        """Discover AWS Network Firewall rules"""
        # This would be implemented as a separate collector
        # For now, return placeholder
        return {'network_firewalls': {region: [] for region in regions}}
    
    # Removed placeholder collectors for RDS/ELB; using dedicated collectors
    
    def _discover_mongodb_atlas(self, regions: List[str]) -> Dict[str, Any]:
        """Discover MongoDB Atlas connections (placeholder implementation)"""
        # This would integrate with MongoDB Atlas API
        return {'connections': [], 'peering_connections': []}
    
    def _discover_databricks(self, regions: List[str]) -> Dict[str, Any]:
        """Discover Databricks connections (placeholder implementation)"""
        # This would integrate with Databricks API
        return {'workspaces': [], 'vpc_connections': []}
    
    def _calculate_resource_counts(self, discovery_data: Dict[str, Any]) -> None:
        """Calculate resource counts for metadata"""
        counts = {}
        
        # Count EC2 instances
        ec2_count = 0
        for region_data in discovery_data.get('ec2_instances', {}).values():
            ec2_count += len(region_data)
        counts['ec2_instances'] = ec2_count
        
        # Count Lambda functions
        lambda_count = 0
        for region_data in discovery_data.get('lambda_functions', {}).values():
            lambda_count += len(region_data)
        counts['lambda_functions'] = lambda_count
        
        # Count Security Groups
        sg_count = 0
        for region_data in discovery_data.get('security_groups', {}).values():
            sg_count += len(region_data)
        counts['security_groups'] = sg_count
        
        # Count VPC components
        vpc_counts = {}
        for region_data in discovery_data.get('vpc_components', {}).values():
            for component_type, components in region_data.items():
                if component_type not in vpc_counts:
                    vpc_counts[component_type] = 0
                vpc_counts[component_type] += len(components)
        counts.update(vpc_counts)
        
        self.discovery_metadata['resource_counts'] = counts
    
    def _finalize_metadata(self) -> Dict[str, Any]:
        """Finalize discovery metadata"""
        self.discovery_metadata['end_time'] = time.time()
        self.discovery_metadata['duration_seconds'] = (
            self.discovery_metadata['end_time'] - self.discovery_metadata['start_time']
        )
        
        return self.discovery_metadata.copy()
    
    def save_data(self, discovery_data: Dict[str, Any], output_file: str) -> None:
        """
        Save discovery data to JSON file
        
        Args:
            discovery_data: Complete discovery data
            output_file: Output file path
        """
        try:
            # Ensure output directory exists
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
            # Convert datetime objects to strings for JSON serialization
            serializable_data = self._make_json_serializable(discovery_data)
            
            # Save to file with pretty formatting
            with open(output_file, 'w') as f:
                json.dump(
                    serializable_data, 
                    f, 
                    indent=self.config.output.json_indent,
                    default=str
                )
            
            logger.info(f"Discovery data saved to {output_file}")
            
        except Exception as e:
            logger.error(f"Failed to save discovery data: {str(e)}")
            raise
    
    def _make_json_serializable(self, obj: Any) -> Any:
        """Convert objects to JSON-serializable format"""
        if isinstance(obj, dict):
            return {key: self._make_json_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif hasattr(obj, 'isoformat'):  # datetime objects
            return obj.isoformat()
        else:
            return obj
    
    def load_data(self, input_file: str) -> Dict[str, Any]:
        """
        Load discovery data from JSON file
        
        Args:
            input_file: Input file path
            
        Returns:
            Discovery data dictionary
        """
        try:
            with open(input_file, 'r') as f:
                data = json.load(f)
            
            logger.info(f"Discovery data loaded from {input_file}")
            return data
            
        except Exception as e:
            logger.error(f"Failed to load discovery data: {str(e)}")
            raise
