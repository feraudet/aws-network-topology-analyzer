"""
VPC Collector
Collects VPCs, subnets, route tables, and related network components
"""

import logging
from typing import Dict, List, Any, Optional

from .base_collector import BaseCollector


logger = logging.getLogger(__name__)


class VPCCollector(BaseCollector):
    """Collector for VPCs and related network components"""
    
    def get_resource_type(self) -> str:
        return 'vpcs'
    
    def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collect VPCs and related components from specified regions
        
        Args:
            regions: List of AWS regions
            account_ids: Optional list of account IDs
            
        Returns:
            Dictionary containing VPC data by region
        """
        logger.info(f"Collecting VPCs and network components from {len(regions)} regions")
        
        def collect_region_vpcs(region: str) -> Dict[str, Any]:
            return self._collect_vpcs_from_region(region)
        
        results = self._collect_parallel(regions, collect_region_vpcs, "Collecting VPCs")
        
        # Store collected data
        self.collected_data = results
        
        # Calculate totals
        total_vpcs = sum(len(data.get('vpcs', [])) for data in results.values())
        total_subnets = sum(len(data.get('subnets', [])) for data in results.values())
        total_route_tables = sum(len(data.get('route_tables', [])) for data in results.values())
        
        logger.info(f"Collected {total_vpcs} VPCs, {total_subnets} subnets, "
                   f"{total_route_tables} route tables across {len(regions)} regions")
        
        return results
    
    def _collect_vpcs_from_region(self, region: str) -> Dict[str, Any]:
        """
        Collect VPCs and related components from a specific region
        
        Args:
            region: AWS region name
            
        Returns:
            Dictionary containing VPC-related data
        """
        try:
            ec2_client = self._get_client('ec2', region)
            
            # Get current account ID
            sts_client = self._get_client('sts', region)
            account_id = sts_client.get_caller_identity()['Account']
            
            region_data = {
                'vpcs': [],
                'subnets': [],
                'route_tables': [],
                'internet_gateways': [],
                'nat_gateways': [],
                'vpc_endpoints': [],
                'network_acls': [],
                'dhcp_options': [],
            }
            
            # Collect VPCs
            vpcs = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_vpcs')
            )
            
            for vpc in vpcs:
                enriched_vpc = self._enrich_vpc_data(vpc, region, account_id)
                region_data['vpcs'].append(enriched_vpc)
            
            # Collect Subnets
            subnets = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_subnets')
            )
            
            for subnet in subnets:
                enriched_subnet = self._enrich_subnet_data(subnet, region, account_id)
                region_data['subnets'].append(enriched_subnet)
            
            # Collect Route Tables
            route_tables = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_route_tables')
            )
            
            for rt in route_tables:
                enriched_rt = self._enrich_route_table_data(rt, region, account_id)
                region_data['route_tables'].append(enriched_rt)
            
            # Collect Internet Gateways
            igws = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_internet_gateways')
            )
            
            for igw in igws:
                enriched_igw = self._enrich_igw_data(igw, region, account_id)
                region_data['internet_gateways'].append(enriched_igw)
            
            # Collect NAT Gateways
            nat_gws = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_nat_gateways')
            )
            
            for nat_gw in nat_gws:
                enriched_nat_gw = self._enrich_nat_gateway_data(nat_gw, region, account_id)
                region_data['nat_gateways'].append(enriched_nat_gw)
            
            # Collect VPC Endpoints
            vpc_endpoints = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_vpc_endpoints')
            )
            
            for endpoint in vpc_endpoints:
                enriched_endpoint = self._enrich_vpc_endpoint_data(endpoint, region, account_id)
                region_data['vpc_endpoints'].append(enriched_endpoint)
            
            # Collect Network ACLs
            nacls = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_network_acls')
            )
            
            for nacl in nacls:
                enriched_nacl = self._enrich_nacl_data(nacl, region, account_id)
                region_data['network_acls'].append(enriched_nacl)
            
            # Collect DHCP Options
            dhcp_options = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_dhcp_options')
            )
            
            for dhcp in dhcp_options:
                enriched_dhcp = self._enrich_dhcp_options_data(dhcp, region, account_id)
                region_data['dhcp_options'].append(enriched_dhcp)
            
            logger.debug(f"Collected VPC components from region {region}: "
                        f"{len(region_data['vpcs'])} VPCs, "
                        f"{len(region_data['subnets'])} subnets, "
                        f"{len(region_data['route_tables'])} route tables")
            
            return region_data
            
        except Exception as e:
            logger.error(f"Failed to collect VPC data from region {region}: {e}")
            return {
                'vpcs': [], 'subnets': [], 'route_tables': [],
                'internet_gateways': [], 'nat_gateways': [], 'vpc_endpoints': [],
                'network_acls': [], 'dhcp_options': []
            }
    
    def _enrich_vpc_data(self, vpc: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """Enrich VPC data"""
        enriched = self._enrich_resource_data(vpc, region, account_id)
        
        network_info = {
            'VpcId': vpc.get('VpcId'),
            'CidrBlock': vpc.get('CidrBlock'),
            'CidrBlockAssociationSet': vpc.get('CidrBlockAssociationSet', []),
            'Ipv6CidrBlockAssociationSet': vpc.get('Ipv6CidrBlockAssociationSet', []),
            'State': vpc.get('State'),
            'OwnerId': vpc.get('OwnerId'),
            'InstanceTenancy': vpc.get('InstanceTenancy'),
            'IsDefault': vpc.get('IsDefault', False),
            'DhcpOptionsId': vpc.get('DhcpOptionsId'),
            'Tags': {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])},
        }
        
        network_info['Name'] = network_info['Tags'].get('Name', vpc.get('VpcId'))
        enriched.update(network_info)
        return enriched
    
    def _enrich_subnet_data(self, subnet: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """Enrich subnet data"""
        enriched = self._enrich_resource_data(subnet, region, account_id)
        
        network_info = {
            'SubnetId': subnet.get('SubnetId'),
            'VpcId': subnet.get('VpcId'),
            'CidrBlock': subnet.get('CidrBlock'),
            'Ipv6CidrBlockAssociationSet': subnet.get('Ipv6CidrBlockAssociationSet', []),
            'AvailabilityZone': subnet.get('AvailabilityZone'),
            'AvailabilityZoneId': subnet.get('AvailabilityZoneId'),
            'AvailableIpAddressCount': subnet.get('AvailableIpAddressCount'),
            'State': subnet.get('State'),
            'MapPublicIpOnLaunch': subnet.get('MapPublicIpOnLaunch', False),
            'AssignIpv6AddressOnCreation': subnet.get('AssignIpv6AddressOnCreation', False),
            'DefaultForAz': subnet.get('DefaultForAz', False),
            'SubnetArn': subnet.get('SubnetArn'),
            'Tags': {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])},
        }
        
        network_info['Name'] = network_info['Tags'].get('Name', subnet.get('SubnetId'))
        network_info['IsPublic'] = network_info['MapPublicIpOnLaunch']
        
        enriched.update(network_info)
        return enriched
    
    def _enrich_route_table_data(self, rt: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """Enrich route table data"""
        enriched = self._enrich_resource_data(rt, region, account_id)
        
        # Process routes
        routes = []
        for route in rt.get('Routes', []):
            route_info = {
                'DestinationCidrBlock': route.get('DestinationCidrBlock'),
                'DestinationIpv6CidrBlock': route.get('DestinationIpv6CidrBlock'),
                'DestinationPrefixListId': route.get('DestinationPrefixListId'),
                'GatewayId': route.get('GatewayId'),
                'InstanceId': route.get('InstanceId'),
                'InstanceOwnerId': route.get('InstanceOwnerId'),
                'NetworkInterfaceId': route.get('NetworkInterfaceId'),
                'TransitGatewayId': route.get('TransitGatewayId'),
                'VpcPeeringConnectionId': route.get('VpcPeeringConnectionId'),
                'NatGatewayId': route.get('NatGatewayId'),
                'State': route.get('State'),
                'Origin': route.get('Origin'),
            }
            routes.append(route_info)
        
        # Process associations
        associations = []
        for assoc in rt.get('Associations', []):
            assoc_info = {
                'RouteTableAssociationId': assoc.get('RouteTableAssociationId'),
                'SubnetId': assoc.get('SubnetId'),
                'GatewayId': assoc.get('GatewayId'),
                'Main': assoc.get('Main', False),
                'AssociationState': assoc.get('AssociationState', {}),
            }
            associations.append(assoc_info)
        
        network_info = {
            'RouteTableId': rt.get('RouteTableId'),
            'VpcId': rt.get('VpcId'),
            'OwnerId': rt.get('OwnerId'),
            'Routes': routes,
            'Associations': associations,
            'PropagatingVgws': rt.get('PropagatingVgws', []),
            'Tags': {tag['Key']: tag['Value'] for tag in rt.get('Tags', [])},
            # Safely handle None values when checking gateway types
            'HasInternetGateway': any(((r.get('GatewayId') or '')).startswith('igw-') for r in routes),
            'HasNatGateway': any(r.get('NatGatewayId') for r in routes),
            'HasTransitGateway': any(r.get('TransitGatewayId') for r in routes),
            'HasVpcPeering': any(r.get('VpcPeeringConnectionId') for r in routes),
        }
        
        network_info['Name'] = network_info['Tags'].get('Name', rt.get('RouteTableId'))
        enriched.update(network_info)
        return enriched
    
    def _enrich_igw_data(self, igw: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """Enrich Internet Gateway data"""
        enriched = self._enrich_resource_data(igw, region, account_id)
        
        network_info = {
            'InternetGatewayId': igw.get('InternetGatewayId'),
            'OwnerId': igw.get('OwnerId'),
            'Attachments': igw.get('Attachments', []),
            'Tags': {tag['Key']: tag['Value'] for tag in igw.get('Tags', [])},
            'AttachedVpcs': [att.get('VpcId') for att in igw.get('Attachments', [])],
        }
        
        network_info['Name'] = network_info['Tags'].get('Name', igw.get('InternetGatewayId'))
        enriched.update(network_info)
        return enriched
    
    def _enrich_nat_gateway_data(self, nat_gw: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """Enrich NAT Gateway data"""
        enriched = self._enrich_resource_data(nat_gw, region, account_id)
        
        network_info = {
            'NatGatewayId': nat_gw.get('NatGatewayId'),
            'VpcId': nat_gw.get('VpcId'),
            'SubnetId': nat_gw.get('SubnetId'),
            'State': nat_gw.get('State'),
            'ConnectivityType': nat_gw.get('ConnectivityType'),
            'CreateTime': nat_gw.get('CreateTime').isoformat() if nat_gw.get('CreateTime') else None,
            'DeleteTime': nat_gw.get('DeleteTime').isoformat() if nat_gw.get('DeleteTime') else None,
            'NatGatewayAddresses': nat_gw.get('NatGatewayAddresses', []),
            'Tags': {tag['Key']: tag['Value'] for tag in nat_gw.get('Tags', [])},
        }
        
        network_info['Name'] = network_info['Tags'].get('Name', nat_gw.get('NatGatewayId'))
        enriched.update(network_info)
        return enriched
    
    def _enrich_vpc_endpoint_data(self, endpoint: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """Enrich VPC Endpoint data"""
        enriched = self._enrich_resource_data(endpoint, region, account_id)
        
        network_info = {
            'VpcEndpointId': endpoint.get('VpcEndpointId'),
            'VpcEndpointType': endpoint.get('VpcEndpointType'),
            'VpcId': endpoint.get('VpcId'),
            'ServiceName': endpoint.get('ServiceName'),
            'State': endpoint.get('State'),
            'RouteTableIds': endpoint.get('RouteTableIds', []),
            'SubnetIds': endpoint.get('SubnetIds', []),
            'Groups': endpoint.get('Groups', []),
            'SecurityGroupIds': [g.get('GroupId') for g in endpoint.get('Groups', [])],
            'PrivateDnsEnabled': endpoint.get('PrivateDnsEnabled', False),
            'RequesterManaged': endpoint.get('RequesterManaged', False),
            'NetworkInterfaceIds': endpoint.get('NetworkInterfaceIds', []),
            'DnsEntries': endpoint.get('DnsEntries', []),
            'CreationTimestamp': endpoint.get('CreationTimestamp').isoformat() if endpoint.get('CreationTimestamp') else None,
            'Tags': {tag['Key']: tag['Value'] for tag in endpoint.get('Tags', [])},
        }
        
        network_info['Name'] = network_info['Tags'].get('Name', endpoint.get('VpcEndpointId'))
        enriched.update(network_info)
        return enriched
    
    def _enrich_nacl_data(self, nacl: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """Enrich Network ACL data"""
        enriched = self._enrich_resource_data(nacl, region, account_id)
        
        # Process entries
        entries = []
        for entry in nacl.get('Entries', []):
            entry_info = {
                'RuleNumber': entry.get('RuleNumber'),
                'Protocol': entry.get('Protocol'),
                'RuleAction': entry.get('RuleAction'),
                'CidrBlock': entry.get('CidrBlock'),
                'Ipv6CidrBlock': entry.get('Ipv6CidrBlock'),
                'Egress': entry.get('Egress'),
                'PortRange': entry.get('PortRange', {}),
                'IcmpTypeCode': entry.get('IcmpTypeCode', {}),
            }
            entries.append(entry_info)
        
        # Process associations
        associations = []
        for assoc in nacl.get('Associations', []):
            assoc_info = {
                'NetworkAclAssociationId': assoc.get('NetworkAclAssociationId'),
                'SubnetId': assoc.get('SubnetId'),
            }
            associations.append(assoc_info)
        
        network_info = {
            'NetworkAclId': nacl.get('NetworkAclId'),
            'VpcId': nacl.get('VpcId'),
            'IsDefault': nacl.get('IsDefault', False),
            'OwnerId': nacl.get('OwnerId'),
            'Entries': entries,
            'Associations': associations,
            'AssociatedSubnets': [assoc.get('SubnetId') for assoc in associations],
            'Tags': {tag['Key']: tag['Value'] for tag in nacl.get('Tags', [])},
        }
        
        network_info['Name'] = network_info['Tags'].get('Name', nacl.get('NetworkAclId'))
        enriched.update(network_info)
        return enriched
    
    def _enrich_dhcp_options_data(self, dhcp: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """Enrich DHCP Options data"""
        enriched = self._enrich_resource_data(dhcp, region, account_id)
        
        # Process DHCP configurations
        configurations = {}
        for config in dhcp.get('DhcpConfigurations', []):
            key = config.get('Key')
            values = [v.get('Value') for v in config.get('Values', [])]
            configurations[key] = values
        
        network_info = {
            'DhcpOptionsId': dhcp.get('DhcpOptionsId'),
            'OwnerId': dhcp.get('OwnerId'),
            'DhcpConfigurations': configurations,
            'Tags': {tag['Key']: tag['Value'] for tag in dhcp.get('Tags', [])},
        }
        
        network_info['Name'] = network_info['Tags'].get('Name', dhcp.get('DhcpOptionsId'))
        enriched.update(network_info)
        return enriched
    
    def get_vpcs_by_region(self, region: str) -> List[Dict[str, Any]]:
        """Get VPCs for a specific region"""
        return self.collected_data.get(region, {}).get('vpcs', [])
    
    def get_vpc_by_id(self, vpc_id: str) -> Optional[Dict[str, Any]]:
        """Get VPC by ID"""
        for region_data in self.collected_data.values():
            for vpc in region_data.get('vpcs', []):
                if vpc.get('VpcId') == vpc_id:
                    return vpc
        return None
    
    def get_subnets_by_vpc(self, vpc_id: str) -> List[Dict[str, Any]]:
        """Get subnets for a specific VPC"""
        subnets = []
        for region_data in self.collected_data.values():
            for subnet in region_data.get('subnets', []):
                if subnet.get('VpcId') == vpc_id:
                    subnets.append(subnet)
        return subnets
