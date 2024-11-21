from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, root_validator
import yaml
import os
from importlib import import_module
from typing import Type


class DNSConfig(BaseModel):
    query_name: str = Field(alias="query-name")
    query_type: str = Field(alias="query-type")


class MonitorConfig(BaseModel):
    """Base configuration for all monitor types."""
    name: str
    type: str
    group: Optional[str] = None
    url: str
    interval: str
    conditions: List[str]
    config: Dict[str, Any] = Field(default_factory=dict)
    dns: Optional[DNSConfig] = None

    @root_validator(pre=True)
    def build_config(cls, values):
        """Build the config dict from all extra fields."""
        known_fields = {'name', 'type', 'group', 'url', 'interval', 'conditions', 'dns'}
        config = {}
        for key, value in values.items():
            if key not in known_fields:
                config[key] = value
        values['config'] = config
        return values


class Config(BaseModel):
    """Main configuration class."""
    monitors: List[MonitorConfig]

    @classmethod
    def from_yaml(cls, path: str) -> 'Config':
        """Load configuration from a YAML file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
            # Transform the endpoints list into monitors list
            if 'endpoints' in data:
                monitors = []
                for endpoint in data['endpoints']:
                    # Determine monitor type from config
                    monitor_type = 'dns' if endpoint.get('dns') else 'http'
                    monitor = {
                        'type': monitor_type,
                        **endpoint
                    }
                    monitors.append(monitor)
                data = {'monitors': monitors}
            return cls(**data)

    @classmethod
    def from_env(cls) -> 'Config':
        """Load configuration from environment variable."""
        config_path = os.getenv('PYTHUS_CONFIG_PATH', 'config.yaml')
        return cls.from_yaml(config_path)

    def get_monitor_class(self, monitor_type: str) -> Type:
        """Get the monitor class for a given type."""
        try:
            # First try to import from monitors package
            module = import_module(f'.monitors.{monitor_type}', package='pythus')
            return getattr(module, f'{monitor_type.capitalize()}Monitor')
        except ImportError:
            # Fallback to base monitor package
            module = import_module('.monitor', package='pythus')
            return getattr(module, f'{monitor_type.capitalize()}Monitor')
