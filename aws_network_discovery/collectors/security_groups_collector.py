"""
Security Groups Collector
Collects security groups and their rules
"""

import logging
from typing import Dict, List, Any, Optional

from .base_collector import BaseCollector


logger = logging.getLogger(__name__)


class SecurityGroupsCollector(BaseCollector):
    """Collector for Security Groups"""
    
    def get_resource_type(self) -> str:
        return 'security_groups'
    
    def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Collect Security Groups from specified regions
        
        Args:
            regions: List of AWS regions
            account_ids: Optional list of account IDs
            
        Returns:
            Dictionary containing Security Group data by region
        """
        logger.info(f"Collecting Security Groups from {len(regions)} regions")
        
        def collect_region_sgs(region: str) -> List[Dict[str, Any]]:
            return self._collect_sgs_from_region(region)
        
        results = self._collect_parallel(regions, collect_region_sgs, "Collecting Security Groups")
        
        # Store collected data
        self.collected_data = results
        
        # Calculate totals
        total_sgs = sum(len(sgs) for sgs in results.values())
        logger.info(f"Collected {total_sgs} Security Groups across {len(regions)} regions")
        
        return results
    
    def _collect_sgs_from_region(self, region: str) -> List[Dict[str, Any]]:
        """
        Collect Security Groups from a specific region
        
        Args:
            region: AWS region name
            
        Returns:
            List of Security Group data
        """
        try:
            ec2_client = self._get_client('ec2', region)
            
            # Get current account ID
            sts_client = self._get_client('sts', region)
            account_id = sts_client.get_caller_identity()['Account']
            
            # Collect security groups using pagination
            security_groups = self._retry_operation(
                lambda: self._paginate_results(ec2_client, 'describe_security_groups')
            )
            
            # Enrich each security group with detailed rule analysis
            enriched_sgs = []
            for sg in security_groups:
                enriched_sg = self._enrich_sg_data(sg, region, account_id)
                enriched_sgs.append(enriched_sg)
            
            # Filter based on configuration
            filtered_sgs = self._filter_resources(enriched_sgs)
            
            logger.debug(f"Collected {len(filtered_sgs)} Security Groups from region {region}")
            return filtered_sgs
            
        except Exception as e:
            logger.error(f"Failed to collect Security Groups from region {region}: {e}")
            return []
    
    def _enrich_sg_data(self, sg: Dict[str, Any], region: str, account_id: str) -> Dict[str, Any]:
        """
        Enrich security group data with detailed rule analysis
        
        Args:
            sg: Raw security group data
            region: AWS region
            account_id: AWS account ID
            
        Returns:
            Enriched security group data
        """
        # Start with base enrichment
        enriched = self._enrich_resource_data(sg, region, account_id)
        
        # Process inbound rules
        inbound_rules = []
        for rule in sg.get('IpPermissions', []):
            processed_rule = self._process_sg_rule(rule, 'inbound')
            inbound_rules.append(processed_rule)
        
        # Process outbound rules
        outbound_rules = []
        for rule in sg.get('IpPermissionsEgress', []):
            processed_rule = self._process_sg_rule(rule, 'outbound')
            outbound_rules.append(processed_rule)
        
        # Extract network-specific information
        network_info = {
            'GroupId': sg.get('GroupId'),
            'GroupName': sg.get('GroupName'),
            'Description': sg.get('Description'),
            'VpcId': sg.get('VpcId'),
            'OwnerId': sg.get('OwnerId'),
            
            # Processed rules
            'InboundRules': inbound_rules,
            'OutboundRules': outbound_rules,
            'TotalInboundRules': len(inbound_rules),
            'TotalOutboundRules': len(outbound_rules),
            
            # Rule analysis
            'AllowsAllTraffic': self._allows_all_traffic(inbound_rules, outbound_rules),
            'AllowsInternetAccess': self._allows_internet_access(inbound_rules, outbound_rules),
            'ReferencedSecurityGroups': self._get_referenced_sgs(inbound_rules, outbound_rules),
            'OpenPorts': self._get_open_ports(inbound_rules),
            'RestrictivePorts': self._get_restrictive_ports(inbound_rules),
            
            # Tags
            'Tags': {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])},
        }
        
        # Add name from tags if available
        network_info['Name'] = network_info['Tags'].get('Name', sg.get('GroupName'))
        
        # Merge network info with enriched data
        enriched.update(network_info)
        
        return enriched
    
    def _process_sg_rule(self, rule: Dict[str, Any], direction: str) -> Dict[str, Any]:
        """
        Process a single security group rule
        
        Args:
            rule: Raw security group rule
            direction: 'inbound' or 'outbound'
            
        Returns:
            Processed rule data
        """
        processed_rule = {
            'Direction': direction,
            'IpProtocol': rule.get('IpProtocol'),
            'FromPort': rule.get('FromPort'),
            'ToPort': rule.get('ToPort'),
            'Sources': [],
            'Description': rule.get('Description', ''),
        }
        
        # Determine port range
        if rule.get('IpProtocol') == '-1':
            processed_rule['PortRange'] = 'All'
        elif rule.get('FromPort') == rule.get('ToPort'):
            processed_rule['PortRange'] = str(rule.get('FromPort', 'N/A'))
        else:
            processed_rule['PortRange'] = f"{rule.get('FromPort', 'N/A')}-{rule.get('ToPort', 'N/A')}"
        
        # Process IP ranges
        for ip_range in rule.get('IpRanges', []):
            source = {
                'Type': 'CIDR',
                'Value': ip_range.get('CidrIp'),
                'Description': ip_range.get('Description', ''),
            }
            processed_rule['Sources'].append(source)
        
        # Process IPv6 ranges
        for ipv6_range in rule.get('Ipv6Ranges', []):
            source = {
                'Type': 'IPv6',
                'Value': ipv6_range.get('CidrIpv6'),
                'Description': ipv6_range.get('Description', ''),
            }
            processed_rule['Sources'].append(source)
        
        # Process security group references
        for sg_ref in rule.get('UserIdGroupPairs', []):
            source = {
                'Type': 'SecurityGroup',
                'Value': sg_ref.get('GroupId'),
                'GroupName': sg_ref.get('GroupName'),
                'UserId': sg_ref.get('UserId'),
                'VpcId': sg_ref.get('VpcId'),
                'VpcPeeringConnectionId': sg_ref.get('VpcPeeringConnectionId'),
                'PeeringStatus': sg_ref.get('PeeringStatus'),
                'Description': sg_ref.get('Description', ''),
            }
            processed_rule['Sources'].append(source)
        
        # Process prefix lists
        for prefix_list in rule.get('PrefixListIds', []):
            source = {
                'Type': 'PrefixList',
                'Value': prefix_list.get('PrefixListId'),
                'Description': prefix_list.get('Description', ''),
            }
            processed_rule['Sources'].append(source)
        
        return processed_rule
    
    def _allows_all_traffic(self, inbound_rules: List[Dict], outbound_rules: List[Dict]) -> bool:
        """Check if security group allows all traffic"""
        for rule in inbound_rules + outbound_rules:
            if (rule.get('IpProtocol') == '-1' and 
                any(src.get('Value') == '0.0.0.0/0' for src in rule.get('Sources', []))):
                return True
        return False
    
    def _allows_internet_access(self, inbound_rules: List[Dict], outbound_rules: List[Dict]) -> Dict[str, bool]:
        """Check if security group allows internet access"""
        inbound_internet = any(
            any(src.get('Value') == '0.0.0.0/0' for src in rule.get('Sources', []))
            for rule in inbound_rules
        )
        
        outbound_internet = any(
            any(src.get('Value') == '0.0.0.0/0' for src in rule.get('Sources', []))
            for rule in outbound_rules
        )
        
        return {
            'Inbound': inbound_internet,
            'Outbound': outbound_internet,
        }
    
    def _get_referenced_sgs(self, inbound_rules: List[Dict], outbound_rules: List[Dict]) -> List[str]:
        """Get list of security groups referenced in rules"""
        referenced_sgs = set()
        
        for rule in inbound_rules + outbound_rules:
            for source in rule.get('Sources', []):
                if source.get('Type') == 'SecurityGroup':
                    referenced_sgs.add(source.get('Value'))
        
        return list(referenced_sgs)
    
    def _get_open_ports(self, inbound_rules: List[Dict]) -> List[Dict[str, Any]]:
        """Get ports that are open to the internet"""
        open_ports = []
        
        for rule in inbound_rules:
            has_internet_source = any(
                src.get('Value') == '0.0.0.0/0' for src in rule.get('Sources', [])
            )
            
            if has_internet_source:
                port_info = {
                    'Protocol': rule.get('IpProtocol'),
                    'PortRange': rule.get('PortRange'),
                    'FromPort': rule.get('FromPort'),
                    'ToPort': rule.get('ToPort'),
                }
                open_ports.append(port_info)
        
        return open_ports
    
    def _get_restrictive_ports(self, inbound_rules: List[Dict]) -> List[Dict[str, Any]]:
        """Get ports that have restrictive access (not open to internet)"""
        restrictive_ports = []
        
        for rule in inbound_rules:
            has_internet_source = any(
                src.get('Value') == '0.0.0.0/0' for src in rule.get('Sources', [])
            )
            
            if not has_internet_source and rule.get('Sources'):
                port_info = {
                    'Protocol': rule.get('IpProtocol'),
                    'PortRange': rule.get('PortRange'),
                    'FromPort': rule.get('FromPort'),
                    'ToPort': rule.get('ToPort'),
                    'SourceCount': len(rule.get('Sources', [])),
                }
                restrictive_ports.append(port_info)
        
        return restrictive_ports
    
    def get_sgs_by_vpc(self, vpc_id: str) -> List[Dict[str, Any]]:
        """Get security groups filtered by VPC ID"""
        sgs = []
        for region_sgs in self.collected_data.values():
            for sg in region_sgs:
                if sg.get('VpcId') == vpc_id:
                    sgs.append(sg)
        return sgs
    
    def get_sg_by_id(self, sg_id: str) -> Optional[Dict[str, Any]]:
        """Get security group by ID"""
        for region_sgs in self.collected_data.values():
            for sg in region_sgs:
                if sg.get('GroupId') == sg_id:
                    return sg
        return None
    
    def get_sgs_with_internet_access(self) -> List[Dict[str, Any]]:
        """Get security groups that allow internet access"""
        internet_sgs = []
        for region_sgs in self.collected_data.values():
            for sg in region_sgs:
                internet_access = sg.get('AllowsInternetAccess', {})
                if internet_access.get('Inbound') or internet_access.get('Outbound'):
                    internet_sgs.append(sg)
        return internet_sgs
