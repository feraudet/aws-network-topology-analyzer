"""
Tests for configuration management
"""

import pytest
import tempfile
import os
from pathlib import Path

from aws_network_discovery.config.settings import Config, DiscoveryConfig, AnalysisConfig


class TestConfig:
    """Test configuration management"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = Config()
        
        assert config.discovery.batch_size == 100
        assert config.discovery.max_retries == 3
        assert config.analysis.max_path_depth == 10
        assert config.output.json_indent == 2
        assert config.auth.sso_region == 'us-east-1'
    
    def test_config_from_file(self):
        """Test loading configuration from YAML file"""
        config_content = """
discovery:
  batch_size: 50
  max_retries: 5

analysis:
  max_path_depth: 15

output:
  json_indent: 4
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            config_file = f.name
        
        try:
            config = Config(config_file=config_file)
            
            assert config.discovery.batch_size == 50
            assert config.discovery.max_retries == 5
            assert config.analysis.max_path_depth == 15
            assert config.output.json_indent == 4
            
        finally:
            os.unlink(config_file)
    
    def test_config_from_env(self):
        """Test loading configuration from environment variables"""
        # Set environment variables
        os.environ['AWS_NETWORK_DISCOVERY_BATCH_SIZE'] = '75'
        os.environ['AWS_NETWORK_DISCOVERY_MAX_RETRIES'] = '7'
        os.environ['AWS_NETWORK_ANALYSIS_MAX_PATH_DEPTH'] = '20'
        
        try:
            config = Config()
            
            assert config.discovery.batch_size == 75
            assert config.discovery.max_retries == 7
            assert config.analysis.max_path_depth == 20
            
        finally:
            # Clean up environment variables
            for var in ['AWS_NETWORK_DISCOVERY_BATCH_SIZE', 'AWS_NETWORK_DISCOVERY_MAX_RETRIES', 
                       'AWS_NETWORK_ANALYSIS_MAX_PATH_DEPTH']:
                if var in os.environ:
                    del os.environ[var]
    
    def test_config_to_dict(self):
        """Test converting configuration to dictionary"""
        config = Config()
        config_dict = config.to_dict()
        
        assert 'discovery' in config_dict
        assert 'analysis' in config_dict
        assert 'output' in config_dict
        assert 'auth' in config_dict
        
        assert config_dict['discovery']['batch_size'] == 100
        assert config_dict['analysis']['max_path_depth'] == 10
    
    def test_save_config_to_file(self):
        """Test saving configuration to file"""
        config = Config()
        config.discovery.batch_size = 200
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config_file = f.name
        
        try:
            config.save_to_file(config_file)
            
            # Load the saved config
            new_config = Config(config_file=config_file)
            assert new_config.discovery.batch_size == 200
            
        finally:
            os.unlink(config_file)
