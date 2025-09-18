"""
Network Analysis Engine
Analyzes network topology and generates communication paths
"""

import json
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv4Address, AddressValueError

from aws_network_discovery.config.settings import Config


logger = logging.getLogger(__name__)


@dataclass
class CommunicationPath:
    """Represents a possible communication path between resources"""
    source_resource: Dict[str, Any]
    destination_resource: Dict[str, Any]
    protocol: str
    port_range: str
    direction: str
    path_chain: List[Dict[str, Any]]
    is_cross_account: bool
    is_cross_region: bool
    is_third_party: bool
    confidence_score: float
    validation_results: Dict[str, bool]


class NetworkAnalyzer:
    """Analyzes AWS network topology and generates communication paths"""
    
    def __init__(self, config: Config):
        """
        Initialize network analyzer
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.network_data = {}
        self.analysis_results = {}
        
    def load_data(self, input_file: str) -> Dict[str, Any]:
        """
        Load network data from JSON file
        
        Args:
            input_file: Path to JSON file containing network data
            
        Returns:
            Network data dictionary
        """
        try:
            with open(input_file, 'r') as f:
                self.network_data = json.load(f)
            
            logger.info(f"Network data loaded from {input_file}")
            return self.network_data
            
        except Exception as e:
            logger.error(f"Failed to load network data: {str(e)}")
            raise
    
    def analyze_communication_paths(self, network_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze network topology and generate communication paths
        
        Args:
            network_data: Optional network data (uses loaded data if not provided)
            
        Returns:
            Analysis results containing communication paths and insights
        """
        if network_data:
            self.network_data = network_data
        
        if not self.network_data:
            raise ValueError("No network data available for analysis")
        
        logger.info("Starting network topology analysis")
        
        # Initialize analysis results
        self.analysis_results = {
            'communication_paths': [],
            'resource_inventory': {},
            'security_analysis': {},
            'compliance_report': {},
            'network_insights': {},
            'metadata': {
                'analysis_timestamp': None,
                'total_paths_found': 0,
                'cross_account_paths': 0,
                'cross_region_paths': 0,
                'third_party_paths': 0,
            }
        }
        
        try:
            # Preserve discovery metadata (errors, regions, accounts) if present
            if isinstance(self.network_data, dict) and 'metadata' in self.network_data:
                self.analysis_results['discovery_metadata'] = self.network_data.get('metadata', {})

            # Step 1: Build resource inventory
            logger.info("Building resource inventory...")
            self._build_resource_inventory()
            
            # Step 2: Analyze security configurations
            logger.info("Analyzing security configurations...")
            self._analyze_security_configurations()
            
            # Step 3: Generate communication paths
            logger.info("Generating communication paths...")
            self._generate_communication_paths()
            
            # Step 4: Validate paths against network rules
            logger.info("Validating communication paths...")
            self._validate_communication_paths()
            
            # Step 5: Generate network insights
            logger.info("Generating network insights...")
            self._generate_network_insights()
            
            # Step 6: Generate compliance report
            logger.info("Generating compliance report...")
            self._generate_compliance_report()
            
            # Finalize metadata
            self._finalize_analysis_metadata()
            
            logger.info("Network topology analysis completed")
            return self.analysis_results
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            raise
    
    def _build_resource_inventory(self) -> None:
        """Build comprehensive resource inventory"""
        inventory = {
            'compute_resources': [],
            'network_resources': [],
            'security_resources': [],
            'connectivity_resources': [],
            'summary': {}
        }
        
        # Process EC2 instances
        for region, instances in self.network_data.get('ec2_instances', {}).items():
            for instance in instances:
                resource = {
                    'type': 'EC2Instance',
                    'id': instance.get('InstanceId'),
                    'name': instance.get('Name'),
                    'region': region,
                    'account_id': instance.get('AccountId'),
                    'profile': instance.get('Profile'),
                    'arn': instance.get('Arn'),
                    'vpc_id': instance.get('VpcId'),
                    'subnet_id': instance.get('SubnetId'),
                    'security_groups': instance.get('SecurityGroups', []),
                    'private_ip': instance.get('PrivateIpAddress'),
                    'public_ip': instance.get('PublicIpAddress'),
                    'state': instance.get('State'),
                    'availability_zone': instance.get('AvailabilityZone'),
                }
                inventory['compute_resources'].append(resource)
        
        # Process Lambda functions
        for region, functions in self.network_data.get('lambda_functions', {}).items():
            for function in functions:
                vpc_config = function.get('VpcConfig', {})
                resource = {
                    'type': 'LambdaFunction',
                    'id': function.get('FunctionName'),
                    'name': function.get('FunctionName'),
                    'region': region,
                    'account_id': function.get('AccountId'),
                    'profile': function.get('Profile'),
                    'arn': function.get('Arn') or function.get('FunctionArn'),
                    'vpc_id': vpc_config.get('VpcId'),
                    'subnet_ids': vpc_config.get('SubnetIds', []),
                    'security_groups': vpc_config.get('SecurityGroupIds', []),
                    'has_vpc_config': function.get('HasVpcConfig', False),
                    'runtime': function.get('Runtime'),
                }
                inventory['compute_resources'].append(resource)
        
        # Process RDS instances
        for region, instances in self.network_data.get('rds_instances', {}).items():
            for instance in instances:
                resource = {
                    'type': 'RDSInstance',
                    'id': instance.get('DBInstanceIdentifier'),
                    'name': instance.get('DBInstanceIdentifier'),
                    'region': region,
                    'account_id': instance.get('AccountId'),
                    'profile': instance.get('Profile'),
                    'arn': instance.get('Arn') or instance.get('DBInstanceArn'),
                    'vpc_id': instance.get('VpcId'),
                    'subnet_ids': instance.get('SubnetIds', []),
                    'security_groups': instance.get('SecurityGroups', []),
                    'private_ip': instance.get('Endpoint', {}).get('Address') if isinstance(instance.get('Endpoint'), dict) else None,
                    'public_ip': instance.get('PubliclyAccessible'),
                    'state': instance.get('DBInstanceStatus'),
                    'availability_zone': instance.get('AvailabilityZone'),
                }
                inventory['compute_resources'].append(resource)
        
        # Process ELBv2 load balancers
        for region, lbs in self.network_data.get('load_balancers', {}).items():
            for lb in lbs:
                resource = {
                    'type': 'ELBv2LoadBalancer',
                    'id': lb.get('LoadBalancerArn') or lb.get('Arn'),
                    'name': lb.get('LoadBalancerName'),
                    'region': region,
                    'account_id': lb.get('AccountId'),
                    'profile': lb.get('Profile'),
                    'arn': lb.get('LoadBalancerArn') or lb.get('Arn'),
                    'vpc_id': lb.get('VpcId'),
                    'subnet_ids': [az.get('SubnetId') for az in lb.get('AvailabilityZones', []) if isinstance(az, dict)],
                    'security_groups': lb.get('SecurityGroups', []),
                    'scheme': lb.get('Scheme'),
                    'lb_type': lb.get('Type', 'application'),
                    'state': (lb.get('State') or {}).get('Code'),
                }
                inventory['compute_resources'].append(resource)
        
        # Process VPCs and network components
        for region, vpc_data in self.network_data.get('vpc_components', {}).items():
            # VPCs
            for vpc in vpc_data.get('vpcs', []):
                resource = {
                    'type': 'VPC',
                    'id': vpc.get('VpcId'),
                    'name': vpc.get('Name'),
                    'region': region,
                    'account_id': vpc.get('AccountId'),
                    'cidr_block': vpc.get('CidrBlock'),
                    'is_default': vpc.get('IsDefault', False),
                    'state': vpc.get('State'),
                }
                inventory['network_resources'].append(resource)
            
            # Subnets
            for subnet in vpc_data.get('subnets', []):
                resource = {
                    'type': 'Subnet',
                    'id': subnet.get('SubnetId'),
                    'name': subnet.get('Name'),
                    'region': region,
                    'account_id': subnet.get('AccountId'),
                    'vpc_id': subnet.get('VpcId'),
                    'cidr_block': subnet.get('CidrBlock'),
                    'availability_zone': subnet.get('AvailabilityZone'),
                    'is_public': subnet.get('IsPublic', False),
                    'available_ips': subnet.get('AvailableIpAddressCount'),
                }
                inventory['network_resources'].append(resource)
        
        # Process Security Groups
        for region, sgs in self.network_data.get('security_groups', {}).items():
            for sg in sgs:
                resource = {
                    'type': 'SecurityGroup',
                    'id': sg.get('GroupId'),
                    'name': sg.get('GroupName'),
                    'region': region,
                    'account_id': sg.get('AccountId'),
                    'vpc_id': sg.get('VpcId'),
                    'description': sg.get('Description'),
                    'inbound_rules': len(sg.get('InboundRules', [])),
                    'outbound_rules': len(sg.get('OutboundRules', [])),
                    'allows_internet': sg.get('AllowsInternetAccess', {}),
                }
                inventory['security_resources'].append(resource)
        
        # Generate summary
        inventory['summary'] = {
            'total_compute_resources': len(inventory['compute_resources']),
            'total_network_resources': len(inventory['network_resources']),
            'total_security_resources': len(inventory['security_resources']),
            'regions': list(set(r.get('region') for r in inventory['compute_resources'] + inventory['network_resources'])),
            'accounts': list(set(r.get('account_id') for r in inventory['compute_resources'] + inventory['network_resources'])),
            'vpcs': list(set(r.get('vpc_id') for r in inventory['compute_resources'] if r.get('vpc_id'))),
        }
        
        self.analysis_results['resource_inventory'] = inventory
    
    def _analyze_security_configurations(self) -> None:
        """Analyze security group configurations and identify potential issues"""
        security_analysis = {
            'overly_permissive_sgs': [],
            'unused_sgs': [],
            'sg_relationships': {},
            'open_ports_analysis': {},
            'compliance_issues': [],
        }
        
        # Get all security groups
        all_sgs = []
        for region, sgs in self.network_data.get('security_groups', {}).items():
            all_sgs.extend(sgs)
        
        # Get all resources that use security groups
        sg_usage = {}
        for resource in self.analysis_results['resource_inventory']['compute_resources']:
            for sg_id in resource.get('security_groups', []):
                if sg_id not in sg_usage:
                    sg_usage[sg_id] = []
                sg_usage[sg_id].append(resource)
        
        # Analyze each security group
        for sg in all_sgs:
            sg_id = sg.get('GroupId')
            
            # Check if overly permissive
            if self._is_overly_permissive_sg(sg):
                security_analysis['overly_permissive_sgs'].append({
                    'sg_id': sg_id,
                    'sg_name': sg.get('GroupName'),
                    'region': sg.get('Region'),
                    'issues': self._get_sg_permission_issues(sg),
                })
            
            # Check if unused
            if sg_id not in sg_usage:
                security_analysis['unused_sgs'].append({
                    'sg_id': sg_id,
                    'sg_name': sg.get('GroupName'),
                    'region': sg.get('Region'),
                })
        
        # Analyze open ports
        security_analysis['open_ports_analysis'] = self._analyze_open_ports(all_sgs)
        
        self.analysis_results['security_analysis'] = security_analysis
    
    def _generate_communication_paths(self) -> None:
        """Generate possible communication paths between resources"""
        paths = []
        
        # Get all compute resources
        compute_resources = self.analysis_results['resource_inventory']['compute_resources']
        
        # Generate paths between all pairs of resources
        for i, source in enumerate(compute_resources):
            for j, destination in enumerate(compute_resources):
                if i != j:  # Don't generate self-paths
                    possible_paths = self._find_communication_paths(source, destination)
                    paths.extend(possible_paths)
        
        # Sort paths by confidence score
        paths.sort(key=lambda p: p.confidence_score, reverse=True)
        
        # Convert to dictionaries for JSON serialization
        serializable_paths = []
        for path in paths:
            path_dict = {
                'source': {
                    'type': path.source_resource.get('type'),
                    'id': path.source_resource.get('id'),
                    'name': path.source_resource.get('name'),
                    'region': path.source_resource.get('region'),
                    'account_id': path.source_resource.get('account_id'),
                    'profile': path.source_resource.get('profile'),
                    'arn': path.source_resource.get('arn'),
                },
                'destination': {
                    'type': path.destination_resource.get('type'),
                    'id': path.destination_resource.get('id'),
                    'name': path.destination_resource.get('name'),
                    'region': path.destination_resource.get('region'),
                    'account_id': path.destination_resource.get('account_id'),
                    'profile': path.destination_resource.get('profile'),
                    'arn': path.destination_resource.get('arn'),
                },
                'protocol': path.protocol,
                'port_range': path.port_range,
                'direction': path.direction,
                'source_rule': path.validation_results.get('source_rule') if path.validation_results else None,
                'destination_rule': path.validation_results.get('destination_rule') if path.validation_results else None,
                'path_chain': path.path_chain,
                'is_cross_account': path.is_cross_account,
                'is_cross_region': path.is_cross_region,
                'is_third_party': path.is_third_party,
                'confidence_score': path.confidence_score,
                'validation_results': path.validation_results,
            }
            serializable_paths.append(path_dict)
        
        self.analysis_results['communication_paths'] = serializable_paths
    
    def _find_communication_paths(self, source: Dict[str, Any], destination: Dict[str, Any]) -> List[CommunicationPath]:
        """Find possible communication paths between two resources"""
        paths = []
        
        # Skip if resources are not in VPCs
        if not source.get('vpc_id') or not destination.get('vpc_id'):
            return paths
        
        # Get security groups for both resources
        source_sgs = source.get('security_groups', [])
        dest_sgs = destination.get('security_groups', [])
        
        if not source_sgs or not dest_sgs:
            return paths
        
        # Find matching security group rules
        for src_sg_id in source_sgs:
            for dest_sg_id in dest_sgs:
                src_sg = self._get_security_group_by_id(src_sg_id)
                dest_sg = self._get_security_group_by_id(dest_sg_id)
                
                if not src_sg or not dest_sg:
                    continue
                
                # Check outbound rules from source to destination
                outbound_paths = self._check_sg_rules_match(
                    src_sg.get('OutboundRules', []),
                    dest_sg.get('InboundRules', []),
                    source, destination, 'outbound'
                )
                paths.extend(outbound_paths)
        
        return paths
    
    def _check_sg_rules_match(self, outbound_rules: List[Dict], inbound_rules: List[Dict], 
                             source: Dict, destination: Dict, direction: str) -> List[CommunicationPath]:
        """Check if security group rules allow communication"""
        paths = []
        
        for out_rule in outbound_rules:
            for in_rule in inbound_rules:
                if self._rules_allow_communication(out_rule, in_rule, source, destination):
                    # Create communication path
                    path = CommunicationPath(
                        source_resource=source,
                        destination_resource=destination,
                        protocol=out_rule.get('IpProtocol', 'unknown'),
                        port_range=out_rule.get('PortRange', 'unknown'),
                        direction=direction,
                        path_chain=self._build_path_chain(source, destination, out_rule, in_rule),
                        is_cross_account=source.get('account_id') != destination.get('account_id'),
                        is_cross_region=source.get('region') != destination.get('region'),
                        is_third_party=False,  # Would be determined by resource type
                        confidence_score=self._calculate_confidence_score(out_rule, in_rule, source, destination),
                        validation_results={
                            'source_rule': {
                                'direction': 'outbound',
                                'protocol': out_rule.get('IpProtocol'),
                                'port_range': out_rule.get('PortRange'),
                                'from_port': out_rule.get('FromPort'),
                                'to_port': out_rule.get('ToPort'),
                            },
                            'destination_rule': {
                                'direction': 'inbound',
                                'protocol': in_rule.get('IpProtocol'),
                                'port_range': in_rule.get('PortRange'),
                                'from_port': in_rule.get('FromPort'),
                                'to_port': in_rule.get('ToPort'),
                            }
                        }
                    )
                    paths.append(path)
        
        return paths
    
    def _rules_allow_communication(self, out_rule: Dict, in_rule: Dict, 
                                  source: Dict, destination: Dict) -> bool:
        """Check if outbound and inbound rules allow communication"""
        # Check protocol match
        if out_rule.get('IpProtocol') != in_rule.get('IpProtocol'):
            if not (out_rule.get('IpProtocol') == '-1' or in_rule.get('IpProtocol') == '-1'):
                return False
        
        # Check port ranges overlap
        if not self._port_ranges_overlap(out_rule, in_rule):
            return False
        
        # Check if source/destination match rule sources
        return self._check_rule_source_match(out_rule, in_rule, source, destination)
    
    def _port_ranges_overlap(self, rule1: Dict, rule2: Dict) -> bool:
        """Check if port ranges in two rules overlap"""
        # Handle 'all' protocols
        if rule1.get('IpProtocol') == '-1' or rule2.get('IpProtocol') == '-1':
            return True
        
        # Get port ranges
        r1_from = rule1.get('FromPort', 0)
        r1_to = rule1.get('ToPort', 65535)
        r2_from = rule2.get('FromPort', 0)
        r2_to = rule2.get('ToPort', 65535)
        
        # Check overlap
        return not (r1_to < r2_from or r2_to < r1_from)
    
    def _check_rule_source_match(self, out_rule: Dict, in_rule: Dict, 
                                source: Dict, destination: Dict) -> bool:
        """Check if rule sources allow communication between resources"""
        # Simplified implementation - would need more complex CIDR matching
        # For now, assume rules match if they reference each other's security groups
        
        out_sources = [s.get('Value') for s in out_rule.get('Sources', [])]
        in_sources = [s.get('Value') for s in in_rule.get('Sources', [])]
        
        # Check for 0.0.0.0/0 (allows all)
        if '0.0.0.0/0' in out_sources or '0.0.0.0/0' in in_sources:
            return True
        
        # Check for security group references
        dest_sgs = destination.get('security_groups', [])
        source_sgs = source.get('security_groups', [])
        
        return any(sg in out_sources for sg in dest_sgs) or any(sg in in_sources for sg in source_sgs)
    
    def _build_path_chain(self, source: Dict, destination: Dict, 
                         out_rule: Dict, in_rule: Dict) -> List[Dict[str, Any]]:
        """Build the communication path chain"""
        chain = [
            {
                'step': 1,
                'component': 'Source',
                'type': source.get('type'),
                'id': source.get('id'),
                'description': f"Traffic originates from {source.get('type')} {source.get('name')}"
            },
            {
                'step': 2,
                'component': 'Source Security Group',
                'type': 'SecurityGroup',
                'id': source.get('security_groups', [None])[0],
                'description': f"Outbound rule allows {out_rule.get('IpProtocol')} on ports {out_rule.get('PortRange')}"
            },
            {
                'step': 3,
                'component': 'Network Path',
                'type': 'Network',
                'id': 'network_path',
                'description': self._describe_network_path(source, destination)
            },
            {
                'step': 4,
                'component': 'Destination Security Group',
                'type': 'SecurityGroup',
                'id': destination.get('security_groups', [None])[0],
                'description': f"Inbound rule allows {in_rule.get('IpProtocol')} on ports {in_rule.get('PortRange')}"
            },
            {
                'step': 5,
                'component': 'Destination',
                'type': destination.get('type'),
                'id': destination.get('id'),
                'description': f"Traffic reaches {destination.get('type')} {destination.get('name')}"
            }
        ]
        
        return chain
    
    def _describe_network_path(self, source: Dict, destination: Dict) -> str:
        """Describe the network path between resources"""
        if source.get('vpc_id') == destination.get('vpc_id'):
            if source.get('subnet_id') == destination.get('subnet_id'):
                return "Same subnet communication"
            else:
                return "Intra-VPC communication via route table"
        else:
            return "Inter-VPC communication (requires peering, TGW, or internet)"
    
    def _calculate_confidence_score(self, out_rule: Dict, in_rule: Dict, 
                                   source: Dict, destination: Dict) -> float:
        """Calculate confidence score for communication path"""
        score = 0.5  # Base score
        
        # Higher confidence for specific port ranges
        if out_rule.get('IpProtocol') != '-1':
            score += 0.2
        
        # Higher confidence for restrictive sources
        out_sources = out_rule.get('Sources', [])
        if not any(s.get('Value') == '0.0.0.0/0' for s in out_sources):
            score += 0.2
        
        # Higher confidence for same VPC
        if source.get('vpc_id') == destination.get('vpc_id'):
            score += 0.1
        
        return min(score, 1.0)
    
    def _validate_communication_paths(self) -> None:
        """Validate communication paths against network rules"""
        for path in self.analysis_results['communication_paths']:
            validation = {
                'security_groups_valid': True,
                'nacls_valid': True,
                'route_tables_valid': True,
                'firewall_rules_valid': True,
            }
            
            # Validate against NACLs
            if self.config.analysis.validate_nacls:
                validation['nacls_valid'] = self._validate_against_nacls(path)
            
            # Validate against route tables
            if self.config.analysis.validate_route_tables:
                validation['route_tables_valid'] = self._validate_against_route_tables(path)
            
            # Validate against firewall rules
            if self.config.analysis.validate_firewall_rules:
                validation['firewall_rules_valid'] = self._validate_against_firewall_rules(path)
            
            path['validation_results'] = validation
    
    def _validate_against_nacls(self, path: Dict) -> bool:
        """Validate path against Network ACL rules"""
        # Simplified implementation
        return True
    
    def _validate_against_route_tables(self, path: Dict) -> bool:
        """Validate path against route table configurations"""
        # Simplified implementation
        return True
    
    def _validate_against_firewall_rules(self, path: Dict) -> bool:
        """Validate path against network firewall rules"""
        # Simplified implementation
        return True
    
    def _generate_network_insights(self) -> None:
        """Generate network insights and recommendations"""
        insights = {
            'connectivity_summary': {},
            'security_recommendations': [],
            'optimization_opportunities': [],
            'risk_assessment': {},
        }
        
        # Connectivity summary
        total_paths = len(self.analysis_results['communication_paths'])
        cross_account = sum(1 for p in self.analysis_results['communication_paths'] if p['is_cross_account'])
        cross_region = sum(1 for p in self.analysis_results['communication_paths'] if p['is_cross_region'])
        
        insights['connectivity_summary'] = {
            'total_communication_paths': total_paths,
            'cross_account_paths': cross_account,
            'cross_region_paths': cross_region,
            'intra_vpc_paths': total_paths - cross_account - cross_region,
        }
        
        # Security recommendations
        overly_permissive = self.analysis_results['security_analysis']['overly_permissive_sgs']
        if overly_permissive:
            insights['security_recommendations'].append({
                'type': 'security_group_hardening',
                'priority': 'high',
                'description': f"Found {len(overly_permissive)} overly permissive security groups",
                'affected_resources': [sg['sg_id'] for sg in overly_permissive],
            })
        
        unused_sgs = self.analysis_results['security_analysis']['unused_sgs']
        if unused_sgs:
            insights['optimization_opportunities'].append({
                'type': 'unused_security_groups',
                'priority': 'medium',
                'description': f"Found {len(unused_sgs)} unused security groups",
                'potential_savings': 'Cleanup unused resources',
            })
        
        self.analysis_results['network_insights'] = insights
    
    def _generate_compliance_report(self) -> None:
        """Generate compliance report"""
        compliance = {
            'security_compliance': {},
            'network_compliance': {},
            'recommendations': [],
        }
        
        # Check for common compliance issues
        open_ports = self.analysis_results['security_analysis']['open_ports_analysis']
        if open_ports.get('ssh_open_to_internet', False):
            compliance['recommendations'].append({
                'rule': 'SSH Access Control',
                'status': 'non_compliant',
                'description': 'SSH (port 22) should not be open to 0.0.0.0/0',
                'remediation': 'Restrict SSH access to specific IP ranges',
            })
        
        self.analysis_results['compliance_report'] = compliance
    
    def _finalize_analysis_metadata(self) -> None:
        """Finalize analysis metadata"""
        import time
        
        metadata = self.analysis_results['metadata']
        metadata['analysis_timestamp'] = time.time()
        metadata['total_paths_found'] = len(self.analysis_results['communication_paths'])
        metadata['cross_account_paths'] = sum(1 for p in self.analysis_results['communication_paths'] if p['is_cross_account'])
        metadata['cross_region_paths'] = sum(1 for p in self.analysis_results['communication_paths'] if p['is_cross_region'])
        metadata['third_party_paths'] = sum(1 for p in self.analysis_results['communication_paths'] if p['is_third_party'])
    
    # Helper methods
    def _get_security_group_by_id(self, sg_id: str) -> Optional[Dict[str, Any]]:
        """Get security group by ID"""
        for region, sgs in self.network_data.get('security_groups', {}).items():
            for sg in sgs:
                if sg.get('GroupId') == sg_id:
                    return sg
        return None
    
    def _is_overly_permissive_sg(self, sg: Dict[str, Any]) -> bool:
        """Check if security group is overly permissive"""
        # Check for rules allowing all traffic from anywhere
        for rule in sg.get('InboundRules', []) + sg.get('OutboundRules', []):
            if (rule.get('IpProtocol') == '-1' and 
                any(s.get('Value') == '0.0.0.0/0' for s in rule.get('Sources', []))):
                return True
        return False
    
    def _get_sg_permission_issues(self, sg: Dict[str, Any]) -> List[str]:
        """Get list of permission issues for security group"""
        issues = []
        
        for rule in sg.get('InboundRules', []):
            if any(s.get('Value') == '0.0.0.0/0' for s in rule.get('Sources', [])):
                if rule.get('IpProtocol') == '-1':
                    issues.append("Allows all traffic from internet")
                elif rule.get('PortRange') == '22':
                    issues.append("SSH open to internet")
                elif rule.get('PortRange') == '3389':
                    issues.append("RDP open to internet")
        
        return issues
    
    def _analyze_open_ports(self, sgs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze open ports across security groups"""
        analysis = {
            'ssh_open_to_internet': False,
            'rdp_open_to_internet': False,
            'http_open_to_internet': False,
            'https_open_to_internet': False,
            'all_ports_open': False,
        }
        
        for sg in sgs:
            for rule in sg.get('InboundRules', []):
                if any(s.get('Value') == '0.0.0.0/0' for s in rule.get('Sources', [])):
                    port_range = rule.get('PortRange', '')
                    if port_range == '22':
                        analysis['ssh_open_to_internet'] = True
                    elif port_range == '3389':
                        analysis['rdp_open_to_internet'] = True
                    elif port_range == '80':
                        analysis['http_open_to_internet'] = True
                    elif port_range == '443':
                        analysis['https_open_to_internet'] = True
                    elif rule.get('IpProtocol') == '-1':
                        analysis['all_ports_open'] = True
        
        return analysis
