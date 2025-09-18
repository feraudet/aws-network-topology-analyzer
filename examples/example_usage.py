#!/usr/bin/env python3
"""
Example usage of AWS Network Discovery and Analysis Tool
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from aws_network_discovery.config.settings import Config
from aws_network_discovery.auth.sso_auth import SSOAuthenticator
from aws_network_discovery.discovery.orchestrator import DiscoveryOrchestrator
from aws_network_discovery.analysis.analyzer import NetworkAnalyzer
from aws_network_discovery.outputs.report_generator import ReportGenerator


def example_full_discovery_and_analysis():
    """
    Example: Complete discovery and analysis pipeline
    """
    print("🔍 AWS Network Discovery and Analysis Example")
    print("=" * 50)
    
    # Configuration
    config = Config()
    
    # Regions to analyze
    regions = ['us-east-1', 'eu-west-1', 'eu-central-1']
    
    # SSO Profile (replace with your actual profile)
    sso_profile = 'my-sso-profile'
    
    try:
        # Step 1: Authentication
        print("Step 1: Authenticating with AWS SSO...")
        authenticator = SSOAuthenticator(sso_profile)
        credentials = authenticator.get_credentials()
        print(f"✅ Authenticated as: {credentials.get('Arn', 'Unknown')}")
        
        # Step 2: Discovery
        print("\nStep 2: Discovering AWS resources...")
        orchestrator = DiscoveryOrchestrator(credentials, config)
        network_data = orchestrator.discover_all(regions)
        
        # Save discovery data
        data_file = 'example_network_data.json'
        orchestrator.save_data(network_data, data_file)
        print(f"✅ Discovery data saved to {data_file}")
        
        # Step 3: Analysis
        print("\nStep 3: Analyzing network topology...")
        analyzer = NetworkAnalyzer(config)
        analysis_results = analyzer.analyze_communication_paths(network_data)
        print("✅ Analysis completed")
        
        # Step 4: Report Generation
        print("\nStep 4: Generating reports...")
        report_generator = ReportGenerator(config)
        output_dir = 'example_reports'
        report_generator.generate_all_reports(analysis_results, output_dir)
        print(f"✅ Reports generated in {output_dir}/")
        
        # Step 5: Display Summary
        print("\n📊 Analysis Summary:")
        print("=" * 30)
        
        metadata = analysis_results.get('metadata', {})
        inventory = analysis_results.get('resource_inventory', {}).get('summary', {})
        
        print(f"Total Communication Paths: {metadata.get('total_paths_found', 0)}")
        print(f"Cross-Account Paths: {metadata.get('cross_account_paths', 0)}")
        print(f"Cross-Region Paths: {metadata.get('cross_region_paths', 0)}")
        print(f"Compute Resources: {inventory.get('total_compute_resources', 0)}")
        print(f"Network Resources: {inventory.get('total_network_resources', 0)}")
        print(f"Security Resources: {inventory.get('total_security_resources', 0)}")
        print(f"Regions Analyzed: {', '.join(inventory.get('regions', []))}")
        
        # Security insights
        security_analysis = analysis_results.get('security_analysis', {})
        permissive_sgs = len(security_analysis.get('overly_permissive_sgs', []))
        unused_sgs = len(security_analysis.get('unused_sgs', []))
        
        if permissive_sgs > 0 or unused_sgs > 0:
            print(f"\n⚠️  Security Findings:")
            if permissive_sgs > 0:
                print(f"   - {permissive_sgs} overly permissive security groups")
            if unused_sgs > 0:
                print(f"   - {unused_sgs} unused security groups")
        
        print(f"\n✅ Complete! Check the reports in '{output_dir}/' directory")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False
    
    return True


def example_analysis_only():
    """
    Example: Analysis only from existing data file
    """
    print("📊 Analysis-Only Example")
    print("=" * 30)
    
    data_file = 'example_network_data.json'
    
    if not os.path.exists(data_file):
        print(f"❌ Data file '{data_file}' not found. Run discovery first.")
        return False
    
    try:
        # Load configuration
        config = Config()
        
        # Analyze existing data
        print("Loading and analyzing network data...")
        analyzer = NetworkAnalyzer(config)
        network_data = analyzer.load_data(data_file)
        analysis_results = analyzer.analyze_communication_paths(network_data)
        
        # Generate reports
        print("Generating reports...")
        report_generator = ReportGenerator(config)
        output_dir = 'analysis_only_reports'
        report_generator.generate_all_reports(analysis_results, output_dir)
        
        print(f"✅ Analysis completed! Reports in '{output_dir}/' directory")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False
    
    return True


def example_custom_configuration():
    """
    Example: Using custom configuration
    """
    print("⚙️  Custom Configuration Example")
    print("=" * 35)
    
    # Create custom configuration
    config = Config()
    
    # Customize discovery settings
    config.discovery.batch_size = 50
    config.discovery.parallel_workers = 5
    config.discovery.include_terminated_instances = True
    
    # Customize analysis settings
    config.analysis.include_cross_account = True
    config.analysis.include_cross_region = True
    config.analysis.validate_nacls = True
    
    # Customize output settings
    config.output.json_indent = 4
    config.output.include_compliance_report = True
    
    # Save custom configuration
    config.save_to_file('custom_config.yaml')
    print("✅ Custom configuration saved to 'custom_config.yaml'")
    
    # Load and verify
    loaded_config = Config(config_file='custom_config.yaml')
    print(f"✅ Loaded config - batch_size: {loaded_config.discovery.batch_size}")
    print(f"✅ Loaded config - parallel_workers: {loaded_config.discovery.parallel_workers}")
    
    return True


def example_security_analysis():
    """
    Example: Focus on security analysis
    """
    print("🔒 Security Analysis Example")
    print("=" * 30)
    
    # Mock some network data for demonstration
    mock_network_data = {
        'security_groups': {
            'us-east-1': [
                {
                    'GroupId': 'sg-12345',
                    'GroupName': 'web-sg',
                    'VpcId': 'vpc-12345',
                    'Description': 'Web server security group',
                    'InboundRules': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'PortRange': '22',
                            'Sources': [{'Type': 'CIDR', 'Value': '0.0.0.0/0'}]
                        },
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
        'ec2_instances': {
            'us-east-1': [
                {
                    'InstanceId': 'i-12345',
                    'Name': 'web-server',
                    'VpcId': 'vpc-12345',
                    'SecurityGroups': ['sg-12345'],
                    'AccountId': '123456789012',
                    'Region': 'us-east-1'
                }
            ]
        },
        'lambda_functions': {'us-east-1': []},
        'vpc_components': {'us-east-1': {'vpcs': [], 'subnets': []}}
    }
    
    try:
        config = Config()
        analyzer = NetworkAnalyzer(config)
        
        # Run analysis
        analysis_results = analyzer.analyze_communication_paths(mock_network_data)
        
        # Focus on security findings
        security_analysis = analysis_results.get('security_analysis', {})
        
        print("Security Analysis Results:")
        print("-" * 25)
        
        # Overly permissive security groups
        permissive_sgs = security_analysis.get('overly_permissive_sgs', [])
        if permissive_sgs:
            print(f"⚠️  Found {len(permissive_sgs)} overly permissive security groups:")
            for sg in permissive_sgs:
                print(f"   - {sg['sg_id']} ({sg['sg_name']}): {', '.join(sg.get('issues', []))}")
        
        # Open ports analysis
        open_ports = security_analysis.get('open_ports_analysis', {})
        if open_ports:
            print("\n🔓 Open Ports Analysis:")
            for port_type, is_open in open_ports.items():
                if is_open:
                    print(f"   - {port_type.replace('_', ' ').title()}: ⚠️  OPEN")
        
        # Network insights
        insights = analysis_results.get('network_insights', {})
        recommendations = insights.get('security_recommendations', [])
        if recommendations:
            print(f"\n💡 Security Recommendations:")
            for rec in recommendations:
                print(f"   - {rec.get('description', 'No description')}")
        
        print("\n✅ Security analysis completed")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False
    
    return True


if __name__ == '__main__':
    """
    Run examples based on command line argument
    """
    if len(sys.argv) < 2:
        print("Usage: python example_usage.py <example_type>")
        print("\nAvailable examples:")
        print("  full        - Complete discovery and analysis")
        print("  analysis    - Analysis only from existing data")
        print("  config      - Custom configuration example")
        print("  security    - Security analysis focus")
        sys.exit(1)
    
    example_type = sys.argv[1].lower()
    
    if example_type == 'full':
        success = example_full_discovery_and_analysis()
    elif example_type == 'analysis':
        success = example_analysis_only()
    elif example_type == 'config':
        success = example_custom_configuration()
    elif example_type == 'security':
        success = example_security_analysis()
    else:
        print(f"❌ Unknown example type: {example_type}")
        success = False
    
    sys.exit(0 if success else 1)
