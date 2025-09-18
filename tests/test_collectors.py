"""
Tests for AWS resource collectors with mocking
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import boto3
from moto import mock_ec2, mock_lambda

from aws_network_discovery.config.settings import Config
from aws_network_discovery.collectors.ec2_collector import EC2Collector
from aws_network_discovery.collectors.lambda_collector import LambdaCollector
from aws_network_discovery.collectors.security_groups_collector import SecurityGroupsCollector


class TestEC2Collector:
    """Test EC2 collector with mocked AWS resources"""
    
    @mock_ec2
    def test_collect_ec2_instances(self):
        """Test collecting EC2 instances with moto mocking"""
        # Create mock EC2 resources
        ec2 = boto3.resource('ec2', region_name='us-east-1')
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock='10.0.1.0/24')
        
        # Create security group
        sg = ec2.create_security_group(
            GroupName='test-sg',
            Description='Test security group',
            VpcId=vpc.id
        )
        
        # Launch instance
        instances = ec2.create_instances(
            ImageId='ami-12345678',
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.micro',
            SubnetId=subnet.id,
            SecurityGroupIds=[sg.id]
        )
        
        # Test collector
        config = Config()
        
        # Mock authenticator
        mock_authenticator = Mock()
        mock_authenticator.get_client.return_value = boto3.client('ec2', region_name='us-east-1')
        
        collector = EC2Collector(mock_authenticator, config)
        
        # Mock STS client for account ID
        with patch.object(collector, '_get_client') as mock_get_client:
            mock_ec2_client = boto3.client('ec2', region_name='us-east-1')
            mock_sts_client = Mock()
            mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
            
            def side_effect(service, region):
                if service == 'ec2':
                    return mock_ec2_client
                elif service == 'sts':
                    return mock_sts_client
            
            mock_get_client.side_effect = side_effect
            
            # Collect instances
            results = collector.collect(['us-east-1'])
            
            # Verify results
            assert 'us-east-1' in results
            assert len(results['us-east-1']) == 1
            
            instance_data = results['us-east-1'][0]
            assert instance_data['InstanceType'] == 't2.micro'
            assert instance_data['VpcId'] == vpc.id
            assert instance_data['SubnetId'] == subnet.id
            assert sg.id in instance_data['SecurityGroups']
    
    def test_collect_with_retry(self):
        """Test collector retry mechanism"""
        config = Config()
        config.discovery.max_retries = 2
        
        mock_authenticator = Mock()
        collector = EC2Collector(mock_authenticator, config)
        
        # Mock operation that fails twice then succeeds
        call_count = 0
        def mock_operation():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                from botocore.exceptions import ClientError
                raise ClientError(
                    {'Error': {'Code': 'Throttling', 'Message': 'Rate exceeded'}},
                    'DescribeInstances'
                )
            return "success"
        
        # Test retry mechanism
        result = collector._retry_operation(mock_operation)
        assert result == "success"
        assert call_count == 3


class TestLambdaCollector:
    """Test Lambda collector with mocked AWS resources"""
    
    @mock_lambda
    def test_collect_lambda_functions(self):
        """Test collecting Lambda functions with moto mocking"""
        # Create mock Lambda function
        lambda_client = boto3.client('lambda', region_name='us-east-1')
        
        function_name = 'test-function'
        lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.9',
            Role='arn:aws:iam::123456789012:role/lambda-role',
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': b'fake code'},
            VpcConfig={
                'SubnetIds': ['subnet-12345'],
                'SecurityGroupIds': ['sg-12345']
            }
        )
        
        # Test collector
        config = Config()
        
        # Mock authenticator
        mock_authenticator = Mock()
        mock_authenticator.get_client.return_value = lambda_client
        
        collector = LambdaCollector(mock_authenticator, config)
        
        # Mock STS client for account ID
        with patch.object(collector, '_get_client') as mock_get_client:
            mock_sts_client = Mock()
            mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
            
            def side_effect(service, region):
                if service == 'lambda':
                    return lambda_client
                elif service == 'sts':
                    return mock_sts_client
            
            mock_get_client.side_effect = side_effect
            
            # Collect functions
            results = collector.collect(['us-east-1'])
            
            # Verify results
            assert 'us-east-1' in results
            assert len(results['us-east-1']) == 1
            
            function_data = results['us-east-1'][0]
            assert function_data['FunctionName'] == function_name
            assert function_data['Runtime'] == 'python3.9'
            assert function_data['HasVpcConfig'] == True
            assert 'subnet-12345' in function_data['VpcConfig']['SubnetIds']
            assert 'sg-12345' in function_data['VpcConfig']['SecurityGroupIds']


class TestSecurityGroupsCollector:
    """Test Security Groups collector with mocked AWS resources"""
    
    @mock_ec2
    def test_collect_security_groups(self):
        """Test collecting security groups with moto mocking"""
        # Create mock VPC and security group
        ec2 = boto3.resource('ec2', region_name='us-east-1')
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        
        sg = ec2.create_security_group(
            GroupName='test-sg',
            Description='Test security group',
            VpcId=vpc.id
        )
        
        # Add some rules
        sg.authorize_ingress(
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'UserIdGroupPairs': [{'GroupId': sg.id}]
                }
            ]
        )
        
        # Test collector
        config = Config()
        
        # Mock authenticator
        mock_authenticator = Mock()
        mock_authenticator.get_client.return_value = boto3.client('ec2', region_name='us-east-1')
        
        collector = SecurityGroupsCollector(mock_authenticator, config)
        
        # Mock STS client for account ID
        with patch.object(collector, '_get_client') as mock_get_client:
            mock_ec2_client = boto3.client('ec2', region_name='us-east-1')
            mock_sts_client = Mock()
            mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
            
            def side_effect(service, region):
                if service == 'ec2':
                    return mock_ec2_client
                elif service == 'sts':
                    return mock_sts_client
            
            mock_get_client.side_effect = side_effect
            
            # Collect security groups
            results = collector.collect(['us-east-1'])
            
            # Verify results
            assert 'us-east-1' in results
            
            # Find our test security group
            test_sg = None
            for sg_data in results['us-east-1']:
                if sg_data['GroupName'] == 'test-sg':
                    test_sg = sg_data
                    break
            
            assert test_sg is not None
            assert test_sg['VpcId'] == vpc.id
            assert test_sg['Description'] == 'Test security group'
            assert len(test_sg['InboundRules']) == 2
            
            # Check for internet access detection
            assert test_sg['AllowsInternetAccess']['Inbound'] == True
    
    def test_security_group_analysis(self):
        """Test security group rule analysis"""
        config = Config()
        mock_authenticator = Mock()
        collector = SecurityGroupsCollector(mock_authenticator, config)
        
        # Test overly permissive check
        sg_data = {
            'InboundRules': [
                {
                    'IpProtocol': '-1',
                    'Sources': [{'Type': 'CIDR', 'Value': '0.0.0.0/0'}]
                }
            ],
            'OutboundRules': []
        }
        
        assert collector._is_overly_permissive_sg(sg_data) == True
        
        # Test restrictive security group
        sg_data_restrictive = {
            'InboundRules': [
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'Sources': [{'Type': 'CIDR', 'Value': '10.0.0.0/8'}]
                }
            ],
            'OutboundRules': []
        }
        
        assert collector._is_overly_permissive_sg(sg_data_restrictive) == False


class TestCollectorIntegration:
    """Test collector integration and error handling"""
    
    def test_collector_error_handling(self):
        """Test collector error handling"""
        config = Config()
        
        # Mock authenticator that raises errors
        mock_authenticator = Mock()
        mock_client = Mock()
        mock_client.describe_instances.side_effect = Exception("AWS API Error")
        mock_authenticator.get_client.return_value = mock_client
        
        collector = EC2Collector(mock_authenticator, config)
        
        # Should handle errors gracefully
        results = collector._collect_instances_from_region('us-east-1')
        assert results == []
    
    def test_parallel_collection(self):
        """Test parallel collection across regions"""
        config = Config()
        config.discovery.parallel_workers = 2
        
        mock_authenticator = Mock()
        collector = EC2Collector(mock_authenticator, config)
        
        # Mock collection function
        def mock_collect_func(region):
            return [{'region': region, 'instance_id': f'i-{region}'}]
        
        results = collector._collect_parallel(['us-east-1', 'eu-west-1'], mock_collect_func)
        
        assert 'us-east-1' in results
        assert 'eu-west-1' in results
        assert results['us-east-1'][0]['region'] == 'us-east-1'
        assert results['eu-west-1'][0]['region'] == 'eu-west-1'
