# Changelog

All notable changes to the AWS Network Discovery and Analysis Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of AWS Network Discovery and Analysis Tool
- Bottom-up discovery approach for comprehensive network topology mapping
- Multi-account and multi-region support with SSO authentication
- Support for EC2, Lambda, RDS, Security Groups, VPCs, Subnets, Route Tables
- Network ACL and VPC Endpoint discovery
- Communication path analysis with validation
- Security group analysis and compliance checking
- Multiple output formats: JSON, CSV, Excel, Interactive HTML
- Configurable discovery and analysis parameters
- Comprehensive logging and error handling
- Unit tests with AWS resource mocking
- CLI interface with multiple operation modes

### Security
- SSO authentication for secure AWS access
- Credential caching with configurable session duration
- No hardcoded credentials or sensitive data exposure

## [1.0.0] - 2024-01-XX

### Added
- **Core Discovery Engine**
  - Bottom-up resource discovery following strict order
  - EC2 instance collector with network interface details
  - Lambda function collector with VPC configuration analysis
  - Security Groups collector with rule analysis
  - VPC collector including subnets, route tables, IGWs, NAT gateways
  - Network ACL discovery and rule processing
  - VPC Endpoint discovery (Interface and Gateway types)

- **Authentication & Multi-Account Support**
  - AWS SSO authentication with profile management
  - Multi-account discovery capability
  - Cross-account role assumption support
  - Credential validation and permission checking

- **Network Analysis Engine**
  - Communication path generation between resources
  - Security group rule matching and validation
  - Network ACL rule validation
  - Route table path analysis
  - Cross-account and cross-region path identification
  - Confidence scoring for communication paths

- **Security Analysis**
  - Overly permissive security group detection
  - Unused security group identification
  - Open port analysis (SSH, RDP, HTTP, HTTPS)
  - Internet-accessible resource identification
  - Security compliance checking

- **Report Generation**
  - Structured JSON output with complete topology data
  - CSV exports for tabular analysis
  - Excel workbooks with multiple sheets and formatting
  - Interactive HTML reports with filtering and sorting
  - Customizable report templates

- **Configuration Management**
  - YAML-based configuration files
  - Environment variable overrides
  - Configurable discovery parameters
  - Analysis and output customization options

- **CLI Interface**
  - `discover` command for resource discovery
  - `analyze` command for analysis-only operations
  - `full` command for complete pipeline execution
  - `test-auth` command for authentication verification
  - Flexible region and account specification

- **Quality Assurance**
  - Comprehensive unit test suite
  - AWS resource mocking with moto library
  - Code coverage reporting
  - Type hints and documentation
  - Error handling and retry mechanisms

### Technical Features
- **Parallel Processing**: Multi-threaded resource collection
- **Retry Logic**: Exponential backoff for API throttling
- **Pagination**: Automatic handling of AWS API pagination
- **Filtering**: Configurable resource filtering options
- **Caching**: Credential and data caching capabilities
- **Logging**: Structured logging with configurable levels

### Supported AWS Services
- **Compute**: EC2 Instances, Lambda Functions
- **Networking**: VPCs, Subnets, Route Tables, Internet Gateways, NAT Gateways
- **Security**: Security Groups, Network ACLs
- **Connectivity**: VPC Endpoints, VPC Peering (planned)
- **Load Balancing**: Application Load Balancers (planned)
- **Databases**: RDS Instances (planned)
- **Third-Party**: MongoDB Atlas, Databricks (framework ready)

### Output Formats
- **JSON**: Complete structured data with metadata
- **CSV**: Tabular exports for spreadsheet analysis
- **Excel**: Multi-sheet workbooks with formatting
- **HTML**: Interactive reports with JavaScript filtering

### Configuration Options
- **Discovery**: Batch sizes, retry policies, parallel workers
- **Analysis**: Path depth limits, validation options
- **Output**: Format customization, report sections
- **Authentication**: SSO settings, session management

### Documentation
- Comprehensive README with usage examples
- API documentation with type hints
- Configuration reference
- Troubleshooting guide
- Contributing guidelines

### Examples
- Full discovery and analysis pipeline
- Analysis-only from existing data
- Custom configuration usage
- Security-focused analysis
- Programmatic API usage

---

## Release Notes

### Version 1.0.0 - Initial Release

This is the first stable release of the AWS Network Discovery and Analysis Tool, providing comprehensive network topology discovery and analysis capabilities for multi-account, multi-region AWS environments.

#### Key Highlights
- **Bottom-Up Discovery**: Follows AWS networking hierarchy for accurate topology mapping
- **Multi-Account Support**: Seamless discovery across AWS Organizations
- **Security Analysis**: Identifies security risks and compliance issues
- **Multiple Output Formats**: Flexible reporting for different use cases
- **Production Ready**: Comprehensive testing and error handling

#### Getting Started
```bash
# Install dependencies
pip install -r requirements.txt

# Configure AWS SSO
aws configure sso

# Run discovery
python main.py full --profile my-sso-profile --regions us-east-1,eu-west-1

# View reports
open reports/network_analysis_report.html
```

#### Migration Notes
This is the initial release, so no migration is required.

#### Known Limitations
- RDS and Load Balancer discovery not yet implemented
- Transit Gateway analysis is placeholder
- Network Firewall rules validation is basic
- Cross-account role assumption requires manual setup

#### Upcoming Features (v1.1.0)
- RDS instance discovery and analysis
- Application Load Balancer support
- Enhanced Transit Gateway analysis
- Network Firewall integration
- Performance optimizations
- Additional third-party service integrations

---

For detailed information about each release, see the [GitHub Releases](https://github.com/axa/aws-network-discovery/releases) page.
