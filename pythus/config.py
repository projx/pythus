from typing import List, Optional
from pydantic import BaseModel, Field
import yaml
import os


class DNSConfig(BaseModel):
    query_name: str = Field(alias="query-name")
    query_type: str = Field(alias="query-type")


class Endpoint(BaseModel):
    name: str
    group: Optional[str] = None
    url: str
    interval: str
    conditions: List[str]
    dns: Optional[DNSConfig] = None


class Config(BaseModel):
    endpoints: List[Endpoint]

    @classmethod
    def from_yaml(cls, path: str) -> 'Config':
        """Load configuration from a YAML file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
            return cls(**data)

    @classmethod
    def from_env(cls) -> 'Config':
        """Load configuration from environment variable."""
        config_path = os.getenv('PYTHUS_CONFIG_PATH', 'config.yaml')
        return cls.from_yaml(config_path)
