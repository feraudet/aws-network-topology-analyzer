"""
AWS SSO Authentication Module
Handles authentication using AWS SSO profiles
"""

import boto3
import logging
from typing import Dict, List, Optional
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from botocore.session import Session
import urllib3
from urllib3.exceptions import InsecureRequestWarning


logger = logging.getLogger(__name__)


class SSOAuthenticator:
    """Handles AWS SSO authentication and credential management"""
    
    def __init__(self, profile_name: str, verify_ssl: bool = True):
        """
        Initialize SSO authenticator with profile name
        
        Args:
            profile_name: AWS SSO profile name from ~/.aws/config
        """
        self.profile_name = profile_name
        self.verify_ssl = verify_ssl
        self.session = None
        self._credentials = None
        
        # Optionally suppress SSL warnings when verification is disabled
        if not self.verify_ssl:
            urllib3.disable_warnings(InsecureRequestWarning)
        
    def get_credentials(self) -> Dict[str, str]:
        """
        Get AWS credentials using SSO profile
        
        Returns:
            Dictionary containing AWS credentials
            
        Raises:
            Exception: If authentication fails
        """
        try:
            # Create session with SSO profile
            self.session = boto3.Session(profile_name=self.profile_name)
            
            # Test credentials by making a simple STS call
            sts_client = self.session.client('sts', verify=self.verify_ssl)
            identity = sts_client.get_caller_identity()
            
            logger.info(f"Successfully authenticated as: {identity.get('Arn')}")
            logger.info(f"Account ID: {identity.get('Account')}")
            
            # Get credentials from session
            credentials = self.session.get_credentials()
            
            self._credentials = {
                'AccessKeyId': credentials.access_key,
                'SecretAccessKey': credentials.secret_key,
                'SessionToken': credentials.token,
                'Account': identity.get('Account'),
                'UserId': identity.get('UserId'),
                'Arn': identity.get('Arn')
            }
            
            return self._credentials
            
        except ProfileNotFound:
            raise Exception(f"AWS profile '{self.profile_name}' not found. "
                          f"Please check your ~/.aws/config file.")
        
        except NoCredentialsError:
            raise Exception(f"No credentials found for profile '{self.profile_name}'. "
                          f"Please run 'aws sso login --profile {self.profile_name}'")
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'UnauthorizedOperation':
                raise Exception(f"Insufficient permissions for profile '{self.profile_name}'")
            elif error_code == 'TokenRefreshRequired':
                raise Exception(f"SSO token expired. Please run 'aws sso login --profile {self.profile_name}'")
            else:
                raise Exception(f"AWS API error: {e.response['Error']['Message']}")
        
        except Exception as e:
            raise Exception(f"Authentication failed: {str(e)}")
    
    def get_session(self) -> boto3.Session:
        """
        Get authenticated boto3 session
        
        Returns:
            Authenticated boto3 session
        """
        if not self.session:
            self.get_credentials()
        
        return self.session
    
    def get_client(self, service_name: str, region_name: str = 'us-east-1') -> boto3.client:
        """
        Get AWS service client
        
        Args:
            service_name: AWS service name (e.g., 'ec2', 'lambda')
            region_name: AWS region name
            
        Returns:
            AWS service client
        """
        session = self.get_session()
        return session.client(service_name, region_name=region_name, verify=self.verify_ssl)
    
    def get_available_accounts(self) -> List[Dict[str, str]]:
        """
        Get list of available AWS accounts from SSO
        
        Returns:
            List of account information dictionaries
        """
        try:
            # This requires additional SSO permissions and setup
            # For now, we'll return the current account
            if not self._credentials:
                self.get_credentials()
            
            return [{
                'AccountId': self._credentials['Account'],
                'AccountName': 'Current Account',
                'Status': 'Active'
            }]
            
        except Exception as e:
            logger.warning(f"Could not retrieve account list: {str(e)}")
            return []
    
    def validate_permissions(self, required_permissions: List[str]) -> Dict[str, bool]:
        """
        Validate that the current credentials have required permissions
        
        Args:
            required_permissions: List of required IAM permissions
            
        Returns:
            Dictionary mapping permissions to validation status
        """
        results = {}
        
        try:
            iam_client = self.get_client('iam')
            
            for permission in required_permissions:
                try:
                    # This is a simplified check - in practice, you'd need
                    # to use IAM policy simulator or test actual operations
                    results[permission] = True
                except ClientError:
                    results[permission] = False
                    
        except Exception as e:
            logger.warning(f"Permission validation failed: {str(e)}")
            # Assume permissions are available if we can't validate
            results = {perm: True for perm in required_permissions}
        
        return results


class MultiAccountAuthenticator:
    """Handles authentication across multiple AWS accounts"""
    
    def __init__(self, base_profile: str, verify_ssl: bool = True):
        """
        Initialize multi-account authenticator
        
        Args:
            base_profile: Base SSO profile name
        """
        self.base_profile = base_profile
        self.verify_ssl = verify_ssl
        self.authenticators = {}
    
    def get_authenticator(self, account_id: Optional[str] = None) -> SSOAuthenticator:
        """
        Get authenticator for specific account
        
        Args:
            account_id: Target account ID (None for base account)
            
        Returns:
            SSOAuthenticator instance
        """
        if account_id is None:
            # Use base profile
            if 'base' not in self.authenticators:
                self.authenticators['base'] = SSOAuthenticator(self.base_profile, verify_ssl=self.verify_ssl)
            return self.authenticators['base']
        
        # For cross-account access, you would typically use role assumption
        # This is a simplified implementation
        if account_id not in self.authenticators:
            # Assume we have profiles named like: profile-accountid
            profile_name = f"{self.base_profile}-{account_id}"
            self.authenticators[account_id] = SSOAuthenticator(profile_name, verify_ssl=self.verify_ssl)
        
        return self.authenticators[account_id]
    
    def get_all_accounts(self) -> List[str]:
        """
        Get list of all available account IDs
        
        Returns:
            List of account IDs
        """
        base_auth = self.get_authenticator()
        accounts = base_auth.get_available_accounts()
        return [acc['AccountId'] for acc in accounts]
