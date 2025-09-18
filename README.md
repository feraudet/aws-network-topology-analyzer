# AWS Network Discovery and Analysis Script

A comprehensive tool for discovering and analyzing AWS network topology across multi-account, multi-region environments using SSO authentication.

## Features

- **Multi-account, multi-region discovery** with SSO authentication
- **Bottom-up discovery approach** ensuring accurate communication path mapping
- **Comprehensive resource analysis** including EC2, Lambda, RDS, Security Groups, NACLs, VPCs, ENIs, Route Tables, Transit Gateways, VPC Endpoints
- **Third-party service integration** (MongoDB Atlas, Databricks)
- **Network Firewall rule validation**
- **Multiple output formats** (JSON, CSV, Excel, Interactive HTML)
- **Two-phase operation** (Data Collection + Analysis)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Discovery
```bash
python main.py discover --profile my-sso-profile --regions us-east-1,eu-west-1,eu-central-1
```

### Multi-Profile Discovery
You can specify multiple SSO profiles. Data from each profile is discovered and merged into a single dataset before analysis and report generation.
```bash
python main.py discover \
  --profile sso-profile-a \
  --profile sso-profile-b \
  --regions us-east-1,eu-west-1 \
  --output-file network_data.json
```

### Analysis Only (from existing data)
```bash
python main.py analyze --input-file network_data.json
```

### Full Pipeline
```bash
python main.py full --profile my-sso-profile --regions us-east-1,eu-west-1,eu-central-1 --output-dir ./reports
```

With multiple profiles:
```bash
python main.py full \
  --profile sso-profile-a \
  --profile sso-profile-b \
  --regions us-east-1,eu-west-1 \
  --output-dir ./reports
```

## Configuration

The script supports configuration via:
- Command line arguments
- Configuration file (`config.yaml`)
- Environment variables

## Output

The script generates:
- **Structured JSON**: Complete network topology data
- **CSV Reports**: Tabular data for analysis
- **Excel Workbook**: Multi-sheet report with filters
- **Interactive HTML**: Browser-based report with sorting and filtering

## Architecture

```
aws_network_discovery/
├── collectors/          # AWS resource collectors
├── analyzers/          # Communication path analysis
├── outputs/            # Report generators
├── auth/              # SSO authentication
├── config/            # Configuration management
└── tests/             # Unit tests with mocking
```

## Development

### Running Tests
```bash
pytest tests/ -v
```

### Mocking AWS Resources
The project includes comprehensive mocking capabilities for unit testing without AWS credentials.

## Notes on Accounts and Profiles

- If `--accounts` is not specified, the discovery will default to the account of each provided `--profile`.
- When multiple `--profile` options are provided, discovery runs for each profile and the results are merged. The merged dataset preserves all regions and resources from each profile/account for downstream analysis and reporting.

## License

MIT License
