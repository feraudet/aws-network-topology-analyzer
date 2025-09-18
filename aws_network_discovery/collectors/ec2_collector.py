"""
EC2 Instance Collector
Collects EC2 instances and their associated network information
"""

import logging
from typing import Dict, List, Any, Optional

from .base_collector import BaseCollector


logger = logging.getLogger(__name__)


class EC2Collector(BaseCollector):
    """Collector for EC2 instances"""
    
    def get_resource_type(self) -> str:
        return 'ec2_instances'
    
    def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collect EC2 instances from specified regions
        
        Args:
            regions: List of AWS regions
            account_ids: Optional list of account IDs
            
        Returns:
            Dictionary containing EC2 instance data by region
        """
        logger.info(f"Collecting EC2 instances from {len(regions)} regions")
        
        def collect_region_instances(region: str) -> List[Dict[str, Any]]:
            return self._collect_instances_from_region(region)
        
        results = self._collect_parallel(regions, collect_region_instances, "Collecting EC2 instances")
        
        # Store collected data
        self.collected_data = results
        
        # Calculate totals
        total_instances = sum(len(instances) for instances in results.values())
        logger.info(f"Collected {total_instances} EC2 instances across {len(regions)} regions")
        
        return results
    
    def _collect_instances_from_region(self, region: str) -> List[Dict[str, Any]]:
        """
        Collect EC2 instances from a specific region
        
        Args:
            region: AWS region name
            
        Returns:
            List of EC2 instance data
        """
        try:
            ec2_client = self._get_client('ec2', region)
            
            # Get current account ID
            sts_client = self._get_client('sts', region)
            account_id = sts_client.get_caller_identity()['Account']
            
            # Collect instances using pagination
            instances = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_instances')
            )
            
            # Flatten reservations to get individual instances
            flattened_instances = []
            for reservation in instances:
                for instance in reservation.get('Instances', []):
                    # Enrich with network information
                    enriched_instance = self._enrich_instance_data(instance, region, account_id)
                    flattened_instances.append(enriched_instance)
            
            # Filter based on configuration
            filtered_instances = self._filter_resources(flattened_instances)
            
            logger.debug(f"Collected {len(filtered_instances)} instances from region {region}")
            return filtered_instances
            
        except Exception as e:
            logger.error(f"Failed to collect EC2 instances from region {region}: {e}")
            return []
    
    def _enrich_instance_data(self, instance: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """
        Enrich instance data with network-specific information
        
        Args:
            instance: Raw EC2 instance data
            region: AWS region
            account_id: AWS account ID
            
        Returns:
            Enriched instance data
        """
        # Start with base enrichment
        enriched = self._enrich_resource_data(instance, region, account_id)
        
        # Extract network-specific information
        # Normalize instance state (can be dict {'Name': ...} or plain string)
        state_val = instance.get('State')
        if isinstance(state_val, dict):
            state_name = state_val.get('Name')
        else:
            state_name = state_val

        launch_time = instance.get('LaunchTime')
        if hasattr(launch_time, 'isoformat'):
            launch_time_str = launch_time.isoformat()
        else:
            launch_time_str = str(launch_time) if launch_time is not None else None

        instance_id = instance.get('InstanceId')
        arn = None
        if instance_id and region and account_id:
            arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"

        network_info = {
            'SecurityGroups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
            'SecurityGroupDetails': instance.get('SecurityGroups', []),
            'SubnetId': instance.get('SubnetId'),
            'VpcId': instance.get('VpcId'),
            'PrivateIpAddress': instance.get('PrivateIpAddress'),
            'PublicIpAddress': instance.get('PublicIpAddress'),
            'PrivateDnsName': instance.get('PrivateDnsName'),
            'PublicDnsName': instance.get('PublicDnsName'),
            'NetworkInterfaces': [],
            'AvailabilityZone': instance.get('Placement', {}).get('AvailabilityZone'),
            'InstanceType': instance.get('InstanceType'),
            'State': state_name,
            'LaunchTime': launch_time_str,
            'Arn': arn,
        }
        
        # Process network interfaces
        for eni in instance.get('NetworkInterfaces', []):
            eni_info = {
                'NetworkInterfaceId': eni.get('NetworkInterfaceId'),
                'SubnetId': eni.get('SubnetId'),
                'VpcId': eni.get('VpcId'),
                'PrivateIpAddress': eni.get('PrivateIpAddress'),
                'PrivateIpAddresses': eni.get('PrivateIpAddresses', []),
                'SecurityGroups': [sg['GroupId'] for sg in eni.get('Groups', [])],
                'Association': eni.get('Association', {}),
                'Attachment': eni.get('Attachment', {}),
                'SourceDestCheck': eni.get('SourceDestCheck'),
                'Status': eni.get('Status'),
                'MacAddress': eni.get('MacAddress'),
            }
            network_info['NetworkInterfaces'].append(eni_info)
        
        # Add tags for easier identification
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        network_info['Tags'] = tags
        network_info['Name'] = tags.get('Name', instance.get('InstanceId'))
        
        # Merge network info with enriched data
        enriched.update(network_info)
        
        return enriched
    
    def get_instances_by_vpc(self, vpc_id: str) -> List[Dict[str, Any]]:
        """
        Get instances filtered by VPC ID
        
        Args:
            vpc_id: VPC ID to filter by
            
        Returns:
            List of instances in the specified VPC
        """
        instances = []
        for region_instances in self.collected_data.values():
            for instance in region_instances:
                if instance.get('VpcId') == vpc_id:
                    instances.append(instance)
        
        return instances
    
    def get_instances_by_security_group(self, security_group_id: str) -> List[Dict[str, Any]]:
        """
        Get instances filtered by security group ID
        
        Args:
            security_group_id: Security group ID to filter by
            
        Returns:
            List of instances using the specified security group
        """
        instances = []
        for region_instances in self.collected_data.values():
            for instance in region_instances:
                if security_group_id in instance.get('SecurityGroups', []):
                    instances.append(instance)
        
        return instances
    
    def get_instances_by_subnet(self, subnet_id: str) -> List[Dict[str, Any]]:
        """
        Get instances filtered by subnet ID
        
        Args:
            subnet_id: Subnet ID to filter by
            
        Returns:
            List of instances in the specified subnet
        """
        instances = []
        for region_instances in self.collected_data.values():
            for instance in region_instances:
                if instance.get('SubnetId') == subnet_id:
                    instances.append(instance)
        
        return instances
