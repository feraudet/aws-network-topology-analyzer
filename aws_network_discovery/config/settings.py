"""
Configuration management for AWS Network Discovery
"""

import yaml
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class DiscoveryConfig:
    """Configuration for resource discovery"""
    batch_size: int = 100
    max_retries: int = 3
    retry_delay: float = 1.0
    timeout: int = 300
    parallel_workers: int = 10
    
    # Resource-specific settings
    include_terminated_instances: bool = False
    include_deleted_resources: bool = False
    
    # Third-party services
    mongodb_atlas_enabled: bool = True
    databricks_enabled: bool = True


@dataclass
class AnalysisConfig:
    """Configuration for network analysis"""
    max_path_depth: int = 10
    include_cross_account: bool = True
    include_cross_region: bool = True
    include_third_party: bool = True
    
    # Communication path validation
    validate_security_groups: bool = True
    validate_nacls: bool = True
    validate_route_tables: bool = True
    validate_firewall_rules: bool = True


@dataclass
class OutputConfig:
    """Configuration for output generation"""
    json_indent: int = 2
    csv_delimiter: str = ','
    excel_max_rows: int = 1000000
    html_template: str = 'default'
    
    # Report sections
    include_resource_inventory: bool = True
    include_communication_matrix: bool = True
    include_security_analysis: bool = True
    include_compliance_report: bool = True


@dataclass
class AuthConfig:
    """Configuration for AWS authentication"""
    sso_start_url: Optional[str] = None
    sso_region: str = 'us-east-1'
    session_duration: int = 3600
    cache_credentials: bool = True


class Config:
    """Main configuration class"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.discovery = DiscoveryConfig()
        self.analysis = AnalysisConfig()
        self.output = OutputConfig()
        self.auth = AuthConfig()
        
        # Load from file if provided
        if config_file:
            self.load_from_file(config_file)
        
        # Override with environment variables
        self.load_from_env()
    
    def load_from_file(self, config_file: str) -> None:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
            
            if 'discovery' in config_data:
                self._update_dataclass(self.discovery, config_data['discovery'])
            
            if 'analysis' in config_data:
                self._update_dataclass(self.analysis, config_data['analysis'])
            
            if 'output' in config_data:
                self._update_dataclass(self.output, config_data['output'])
            
            if 'auth' in config_data:
                self._update_dataclass(self.auth, config_data['auth'])
                
        except Exception as e:
            raise ValueError(f"Failed to load configuration from {config_file}: {str(e)}")
    
    def load_from_env(self) -> None:
        """Load configuration from environment variables"""
        env_mappings = {
            'AWS_NETWORK_DISCOVERY_BATCH_SIZE': ('discovery', 'batch_size', int),
            'AWS_NETWORK_DISCOVERY_MAX_RETRIES': ('discovery', 'max_retries', int),
            'AWS_NETWORK_DISCOVERY_TIMEOUT': ('discovery', 'timeout', int),
            'AWS_NETWORK_DISCOVERY_PARALLEL_WORKERS': ('discovery', 'parallel_workers', int),
            'AWS_NETWORK_ANALYSIS_MAX_PATH_DEPTH': ('analysis', 'max_path_depth', int),
            'AWS_NETWORK_OUTPUT_JSON_INDENT': ('output', 'json_indent', int),
            'AWS_SSO_START_URL': ('auth', 'sso_start_url', str),
            'AWS_SSO_REGION': ('auth', 'sso_region', str),
        }
        
        for env_var, (section, attr, type_func) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    converted_value = type_func(value) if type_func != str else value
                    setattr(getattr(self, section), attr, converted_value)
                except ValueError:
                    pass  # Skip invalid values
    
    def _update_dataclass(self, dataclass_instance: Any, config_dict: Dict[str, Any]) -> None:
        """Update dataclass instance with values from dictionary"""
        for key, value in config_dict.items():
            if hasattr(dataclass_instance, key):
                setattr(dataclass_instance, key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'discovery': self.discovery.__dict__,
            'analysis': self.analysis.__dict__,
            'output': self.output.__dict__,
            'auth': self.auth.__dict__,
        }
    
    def save_to_file(self, config_file: str) -> None:
        """Save configuration to YAML file"""
        config_dict = self.to_dict()
        
        # Ensure directory exists
        Path(config_file).parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)


# Default configuration template
DEFAULT_CONFIG_TEMPLATE = """
# AWS Network Discovery Configuration

discovery:
  batch_size: 100
  max_retries: 3
  retry_delay: 1.0
  timeout: 300
  parallel_workers: 10
  include_terminated_instances: false
  include_deleted_resources: false
  mongodb_atlas_enabled: true
  databricks_enabled: true

analysis:
  max_path_depth: 10
  include_cross_account: true
  include_cross_region: true
  include_third_party: true
  validate_security_groups: true
  validate_nacls: true
  validate_route_tables: true
  validate_firewall_rules: true

output:
  json_indent: 2
  csv_delimiter: ','
  excel_max_rows: 1000000
  html_template: 'default'
  include_resource_inventory: true
  include_communication_matrix: true
  include_security_analysis: true
  include_compliance_report: true

auth:
  sso_start_url: null
  sso_region: 'us-east-1'
  session_duration: 3600
  cache_credentials: true
"""
