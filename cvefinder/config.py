"""
Configuration management for CVEFinder CLI
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any


class Config:
    """Configuration manager"""

    def __init__(self):
        self.config_dir = Path.home() / '.cvefinder'
        self.config_file = self.config_dir / 'config.yaml'
        self.config = self.load()

    def load(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if not self.config_file.exists():
            return {
                'default_profile': 'default',
                'profiles': {}
            }

        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f) or {'default_profile': 'default', 'profiles': {}}
        except Exception as e:
            print(f"Warning: Failed to load config: {e}")
            return {'default_profile': 'default', 'profiles': {}}

    def save(self):
        """Save configuration to file"""
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Save config
        with open(self.config_file, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)

        # Set restrictive permissions (user read/write only)
        os.chmod(self.config_file, 0o600)

    def get_profile(self, name: str = 'default') -> Dict[str, Any]:
        """Get profile configuration"""
        # Allow profile override via environment variable
        profile_name = os.getenv('CVEFINDER_PROFILE', name)

        # Check environment variables first
        env_api_key = os.getenv('CVEFINDER_API_KEY')

        # Copy to avoid mutating in-memory config when applying env overrides
        profile = dict(self.config.get('profiles', {}).get(profile_name, {}))

        # Environment variables override config file
        if env_api_key:
            profile['api_key'] = env_api_key

        return profile

    def set_profile(self, name: str, data: Dict[str, Any]):
        """Set profile configuration"""
        if 'profiles' not in self.config:
            self.config['profiles'] = {}

        self.config['profiles'][name] = data

        # Set as default if it's the first profile
        if len(self.config['profiles']) == 1:
            self.config['default_profile'] = name

    def get_default_profile(self) -> str:
        """Get default profile name"""
        return self.config.get('default_profile', 'default')

    def set_default_profile(self, name: str):
        """Set default profile"""
        self.config['default_profile'] = name
