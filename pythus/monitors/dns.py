import aiodns
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime
from .base import BaseMonitor, Check


class ResolveTimeCheck:
    """Check if DNS resolution time is within acceptable range."""
    def __init__(self, max_resolve_time: float):
        self.max_resolve_time = max_resolve_time

    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        resolve_time = data.get('resolve_time', float('inf'))
        success = resolve_time <= self.max_resolve_time
        return {
            'name': 'resolve_time',
            'success': success,
            'message': f'DNS Resolution time: {resolve_time:.2f}s {"<=" if success else ">"} {self.max_resolve_time}s',
        }


class RecordCheck:
    """Check if DNS record matches expected value."""
    def __init__(self, expected_value: str):
        self.expected_value = expected_value

    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        records = data.get('records', [])
        success = any(str(record) == self.expected_value for record in records)
        record_list = ', '.join(str(r) for r in records)
        return {
            'name': 'record',
            'success': success,
            'message': f'DNS Records: [{record_list}] {"match" if success else "do not match"} expected: {self.expected_value}',
        }


class DNSMonitor(BaseMonitor):
    """Monitor for DNS records."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.domain = config['domain']
        self.record_type = config.get('record_type', 'A')
        self.nameserver = config.get('nameserver')
        self.timeout = config.get('timeout', 5)

    def _parse_condition(self, condition: str) -> Optional[Check]:
        """Parse condition string into a Check instance."""
        parts = condition.split()
        
        if len(parts) < 3:
            return None
            
        check_type = parts[0].lower()
        operator = parts[1]
        value = ' '.join(parts[2:])  # Join remaining parts for record checks
        
        if check_type == 'resolve_time' and operator == '<=':
            try:
                max_time = float(value.rstrip('s'))  # Remove 's' suffix if present
                return ResolveTimeCheck(max_time)
            except ValueError:
                return None
                
        elif check_type == 'record' and operator == '==':
            return RecordCheck(value)
            
        return None

    async def gather_data(self) -> Dict[str, Any]:
        """Gather DNS resolution data."""
        start_time = datetime.now()
        
        try:
            # Create resolver with optional nameserver
            resolver = aiodns.DNSResolver()
            if self.nameserver:
                resolver.nameservers = [self.nameserver]
            
            # Set timeout
            resolver.timeout = self.timeout
            
            # Resolve DNS record
            records = await resolver.query(self.domain, self.record_type)
            end_time = datetime.now()
            resolve_time = (end_time - start_time).total_seconds()
            
            # Format records based on type
            formatted_records = []
            for record in records:
                if self.record_type == 'A':
                    formatted_records.append(record.host)
                elif self.record_type == 'AAAA':
                    formatted_records.append(record.host)
                elif self.record_type == 'CNAME':
                    formatted_records.append(record.cname)
                elif self.record_type == 'MX':
                    formatted_records.append(f'{record.host} (priority: {record.priority})')
                elif self.record_type == 'TXT':
                    formatted_records.append(' '.join(record.text))
                else:
                    formatted_records.append(str(record))
            
            return {
                'records': formatted_records,
                'resolve_time': resolve_time,
                'record_type': self.record_type,
            }
            
        except asyncio.TimeoutError:
            end_time = datetime.now()
            resolve_time = (end_time - start_time).total_seconds()
            raise Exception(f'DNS resolution timed out after {resolve_time:.2f}s')
            
        except Exception as e:
            end_time = datetime.now()
            resolve_time = (end_time - start_time).total_seconds()
            raise Exception(f'DNS resolution failed: {str(e)}')

    def get_relevant_data_keys(self, check_name: str) -> List[str]:
        """Get relevant data keys for each check type."""
        if check_name == 'resolve_time':
            return ['resolve_time']
        elif check_name == 'record':
            return ['records', 'record_type']
        else:
            return super().get_relevant_data_keys(check_name)
