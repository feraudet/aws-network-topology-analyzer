"""
Tests for network analyzer
"""

import pytest
import json
import tempfile
from unittest.mock import Mock, patch

from aws_network_discovery.config.settings import Config
from aws_network_discovery.analysis.analyzer import NetworkAnalyzer, CommunicationPath


class TestNetworkAnalyzer:
    """Test network analyzer functionality"""
    
    def test_load_data(self):
        """Test loading network data from JSON file"""
        test_data = {
            'ec2_instances': {
                'us-east-1': [
                    {
                        'InstanceId': 'i-12345',
                        'InstanceType': 't2.micro',
                        'VpcId': 'vpc-12345',
                        'SecurityGroups': ['sg-12345']
                    }
                ]
            },
            'security_groups': {
                'us-east-1': [
                    {
                        'GroupId': 'sg-12345',
                        'GroupName': 'test-sg',
                        'VpcId': 'vpc-12345'
                    }
                ]
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_data, f)
            json_file = f.name
        
        try:
            config = Config()
            analyzer = NetworkAnalyzer(config)
            
            loaded_data = analyzer.load_data(json_file)
            
            assert loaded_data == test_data
            assert analyzer.network_data == test_data
            
        finally:
            import os
            os.unlink(json_file)
    
    def test_build_resource_inventory(self):
        """Test building resource inventory"""
        config = Config()
        analyzer = NetworkAnalyzer(config)
        
        # Mock network data
        analyzer.network_data = {
            'ec2_instances': {
                'us-east-1': [
                    {
                        'InstanceId': 'i-12345',
                        'Name': 'test-instance',
                        'InstanceType': 't2.micro',
                        'VpcId': 'vpc-12345',
                        'SubnetId': 'subnet-12345',
                        'SecurityGroups': ['sg-12345'],
                        'PrivateIpAddress': '10.0.1.10',
                        'State': 'running',
                        'AvailabilityZone': 'us-east-1a',
                        'AccountId': '123456789012',
                        'Region': 'us-east-1'
                    }
                ]
            },
            'lambda_functions': {
                'us-east-1': [
                    {
                        'FunctionName': 'test-function',
                        'Runtime': 'python3.9',
                        'VpcConfig': {
                            'VpcId': 'vpc-12345',
                            'SubnetIds': ['subnet-12345'],
                            'SecurityGroupIds': ['sg-12345']
                        },
                        'HasVpcConfig': True,
                        'AccountId': '123456789012',
                        'Region': 'us-east-1'
                    }
                ]
            },
            'security_groups': {
                'us-east-1': [
                    {
                        'GroupId': 'sg-12345',
                        'GroupName': 'test-sg',
                        'VpcId': 'vpc-12345',
                        'Description': 'Test security group',
                        'InboundRules': [],
                        'OutboundRules': [],
                        'AccountId': '123456789012',
                        'Region': 'us-east-1'
                    }
                ]
            },
            'vpc_components': {
                'us-east-1': {
                    'vpcs': [
                        {
                            'VpcId': 'vpc-12345',
                            'Name': 'test-vpc',
                            'CidrBlock': '10.0.0.0/16',
                            'IsDefault': False,
                            'State': 'available',
                            'AccountId': '123456789012',
                            'Region': 'us-east-1'
                        }
                    ],
                    'subnets': [
                        {
                            'SubnetId': 'subnet-12345',
                            'Name': 'test-subnet',
                            'VpcId': 'vpc-12345',
                            'CidrBlock': '10.0.1.0/24',
                            'AvailabilityZone': 'us-east-1a',
                            'IsPublic': False,
                            'AvailableIpAddressCount': 250,
                            'AccountId': '123456789012',
                            'Region': 'us-east-1'
                        }
                    ]
                }
            }
        }
        
        # Initialize analysis results
        analyzer.analysis_results = {
            'resource_inventory': {},
            'security_analysis': {},
            'communication_paths': [],
            'network_insights': {},
            'compliance_report': {},
            'metadata': {}
        }
        
        # Build inventory
        analyzer._build_resource_inventory()
        
        inventory = analyzer.analysis_results['resource_inventory']
        
        # Verify compute resources
        assert len(inventory['compute_resources']) == 2  # 1 EC2 + 1 Lambda
        
        ec2_resource = next(r for r in inventory['compute_resources'] if r['type'] == 'EC2Instance')
        assert ec2_resource['id'] == 'i-12345'
        assert ec2_resource['vpc_id'] == 'vpc-12345'
        assert ec2_resource['security_groups'] == ['sg-12345']
        
        lambda_resource = next(r for r in inventory['compute_resources'] if r['type'] == 'LambdaFunction')
        assert lambda_resource['id'] == 'test-function'
        assert lambda_resource['vpc_id'] == 'vpc-12345'
        assert lambda_resource['has_vpc_config'] == True
        
        # Verify network resources
        assert len(inventory['network_resources']) == 2  # 1 VPC + 1 Subnet
        
        vpc_resource = next(r for r in inventory['network_resources'] if r['type'] == 'VPC')
        assert vpc_resource['id'] == 'vpc-12345'
        assert vpc_resource['cidr_block'] == '10.0.0.0/16'
        
        # Verify security resources
        assert len(inventory['security_resources']) == 1
        
        sg_resource = inventory['security_resources'][0]
        assert sg_resource['id'] == 'sg-12345'
        assert sg_resource['vpc_id'] == 'vpc-12345'
        
        # Verify summary
        summary = inventory['summary']
        assert summary['total_compute_resources'] == 2
        assert summary['total_network_resources'] == 2
        assert summary['total_security_resources'] == 1
        assert 'us-east-1' in summary['regions']
        assert '123456789012' in summary['accounts']
    
    def test_security_analysis(self):
        """Test security configuration analysis"""
        config = Config()
        analyzer = NetworkAnalyzer(config)
        
        # Mock network data with security groups
        analyzer.network_data = {
            'security_groups': {
                'us-east-1': [
                    {
                        'GroupId': 'sg-permissive',
                        'GroupName': 'permissive-sg',
                        'Region': 'us-east-1',
                        'InboundRules': [
                            {
                                'IpProtocol': '-1',
                                'Sources': [{'Type': 'CIDR', 'Value': '0.0.0.0/0'}]
                            }
                        ],
                        'OutboundRules': []
                    },
                    {
                        'GroupId': 'sg-unused',
                        'GroupName': 'unused-sg',
                        'Region': 'us-east-1',
                        'InboundRules': [],
                        'OutboundRules': []
                    }
                ]
            }
        }
        
        # Mock resource inventory with no resources using sg-unused
        analyzer.analysis_results = {
            'resource_inventory': {
                'compute_resources': [
                    {
                        'type': 'EC2Instance',
                        'id': 'i-12345',
                        'security_groups': ['sg-permissive']  # Only uses permissive SG
                    }
                ]
            },
            'security_analysis': {}
        }
        
        # Analyze security configurations
        analyzer._analyze_security_configurations()
        
        security_analysis = analyzer.analysis_results['security_analysis']
        
        # Check overly permissive SGs
        assert len(security_analysis['overly_permissive_sgs']) == 1
        permissive_sg = security_analysis['overly_permissive_sgs'][0]
        assert permissive_sg['sg_id'] == 'sg-permissive'
        
        # Check unused SGs
        assert len(security_analysis['unused_sgs']) == 1
        unused_sg = security_analysis['unused_sgs'][0]
        assert unused_sg['sg_id'] == 'sg-unused'
    
    def test_communication_path_generation(self):
        """Test communication path generation"""
        config = Config()
        analyzer = NetworkAnalyzer(config)
        
        # Mock complete network data
        analyzer.network_data = {
            'security_groups': {
                'us-east-1': [
                    {
                        'GroupId': 'sg-web',
                        'OutboundRules': [
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 3306,
                                'ToPort': 3306,
                                'PortRange': '3306',
                                'Sources': [{'Type': 'SecurityGroup', 'Value': 'sg-db'}]
                            }
                        ]
                    },
                    {
                        'GroupId': 'sg-db',
                        'InboundRules': [
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 3306,
                                'ToPort': 3306,
                                'PortRange': '3306',
                                'Sources': [{'Type': 'SecurityGroup', 'Value': 'sg-web'}]
                            }
                        ]
                    }
                ]
            }
        }
        
        # Mock resource inventory
        analyzer.analysis_results = {
            'resource_inventory': {
                'compute_resources': [
                    {
                        'type': 'EC2Instance',
                        'id': 'i-web',
                        'name': 'web-server',
                        'region': 'us-east-1',
                        'account_id': '123456789012',
                        'vpc_id': 'vpc-12345',
                        'security_groups': ['sg-web']
                    },
                    {
                        'type': 'EC2Instance',
                        'id': 'i-db',
                        'name': 'db-server',
                        'region': 'us-east-1',
                        'account_id': '123456789012',
                        'vpc_id': 'vpc-12345',
                        'security_groups': ['sg-db']
                    }
                ]
            },
            'communication_paths': []
        }
        
        # Generate communication paths
        analyzer._generate_communication_paths()
        
        paths = analyzer.analysis_results['communication_paths']
        
        # Should find at least one path from web to db
        assert len(paths) > 0
        
        # Find the web->db path
        web_to_db_path = None
        for path in paths:
            if (path['source']['id'] == 'i-web' and 
                path['destination']['id'] == 'i-db' and
                path['protocol'] == 'tcp' and
                path['port_range'] == '3306'):
                web_to_db_path = path
                break
        
        assert web_to_db_path is not None
        assert web_to_db_path['is_cross_account'] == False
        assert web_to_db_path['is_cross_region'] == False
        assert len(web_to_db_path['path_chain']) == 5  # Source -> SG -> Network -> SG -> Destination
    
    def test_network_insights_generation(self):
        """Test network insights generation"""
        config = Config()
        analyzer = NetworkAnalyzer(config)
        
        # Mock analysis results
        analyzer.analysis_results = {
            'communication_paths': [
                {'is_cross_account': True, 'is_cross_region': False},
                {'is_cross_account': False, 'is_cross_region': True},
                {'is_cross_account': False, 'is_cross_region': False}
            ],
            'security_analysis': {
                'overly_permissive_sgs': [
                    {'sg_id': 'sg-1', 'issues': ['SSH open to internet']}
                ],
                'unused_sgs': [
                    {'sg_id': 'sg-unused'}
                ]
            },
            'network_insights': {}
        }
        
        # Generate insights
        analyzer._generate_network_insights()
        
        insights = analyzer.analysis_results['network_insights']
        
        # Check connectivity summary
        connectivity = insights['connectivity_summary']
        assert connectivity['total_communication_paths'] == 3
        assert connectivity['cross_account_paths'] == 1
        assert connectivity['cross_region_paths'] == 1
        assert connectivity['intra_vpc_paths'] == 1  # total - cross_account - cross_region
        
        # Check security recommendations
        assert len(insights['security_recommendations']) == 1
        sec_rec = insights['security_recommendations'][0]
        assert sec_rec['type'] == 'security_group_hardening'
        assert sec_rec['priority'] == 'high'
        
        # Check optimization opportunities
        assert len(insights['optimization_opportunities']) == 1
        opt_opp = insights['optimization_opportunities'][0]
        assert opt_opp['type'] == 'unused_security_groups'
    
    def test_full_analysis_pipeline(self):
        """Test complete analysis pipeline"""
        config = Config()
        analyzer = NetworkAnalyzer(config)
        
        # Create comprehensive test data
        test_network_data = {
            'ec2_instances': {
                'us-east-1': [
                    {
                        'InstanceId': 'i-web',
                        'Name': 'web-server',
                        'InstanceType': 't2.micro',
                        'VpcId': 'vpc-12345',
                        'SubnetId': 'subnet-web',
                        'SecurityGroups': ['sg-web'],
                        'PrivateIpAddress': '10.0.1.10',
                        'State': 'running',
                        'AvailabilityZone': 'us-east-1a',
                        'AccountId': '123456789012',
                        'Region': 'us-east-1'
                    }
                ]
            },
            'lambda_functions': {
                'us-east-1': []
            },
            'security_groups': {
                'us-east-1': [
                    {
                        'GroupId': 'sg-web',
                        'GroupName': 'web-sg',
                        'VpcId': 'vpc-12345',
                        'Description': 'Web server security group',
                        'InboundRules': [
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 80,
                                'ToPort': 80,
                                'PortRange': '80',
                                'Sources': [{'Type': 'CIDR', 'Value': '0.0.0.0/0'}]
                            }
                        ],
                        'OutboundRules': [],
                        'AllowsInternetAccess': {'Inbound': True, 'Outbound': False},
                        'AccountId': '123456789012',
                        'Region': 'us-east-1'
                    }
                ]
            },
            'vpc_components': {
                'us-east-1': {
                    'vpcs': [
                        {
                            'VpcId': 'vpc-12345',
                            'Name': 'main-vpc',
                            'CidrBlock': '10.0.0.0/16',
                            'IsDefault': False,
                            'State': 'available',
                            'AccountId': '123456789012',
                            'Region': 'us-east-1'
                        }
                    ],
                    'subnets': []
                }
            },
            'metadata': {
                'regions': ['us-east-1'],
                'accounts': ['123456789012']
            }
        }
        
        # Run full analysis
        results = analyzer.analyze_communication_paths(test_network_data)
        
        # Verify all sections are present
        assert 'communication_paths' in results
        assert 'resource_inventory' in results
        assert 'security_analysis' in results
        assert 'network_insights' in results
        assert 'compliance_report' in results
        assert 'metadata' in results
        
        # Verify resource inventory
        inventory = results['resource_inventory']
        assert inventory['summary']['total_compute_resources'] == 1
        assert inventory['summary']['total_security_resources'] == 1
        
        # Verify metadata is populated
        metadata = results['metadata']
        assert 'analysis_timestamp' in metadata
        assert 'total_paths_found' in metadata
