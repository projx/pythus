import aiohttp
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime
from .base import BaseMonitor, Check


class ResponseTimeCheck:
    """Check if response time is within acceptable range."""
    def __init__(self, max_response_time: float):
        self.max_response_time = max_response_time

    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        response_time = data.get('response_time', float('inf'))
        success = response_time <= self.max_response_time
        return {
            'name': 'response_time',
            'success': success,
            'message': f'HTTP Response time: {response_time:.2f}s {"<=" if success else ">"} {self.max_response_time}s',
        }


class StatusCodeCheck:
    """Check if status code matches expected value."""
    def __init__(self, expected_status: int):
        self.expected_status = expected_status

    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        status_code = data.get('status_code')
        success = status_code == self.expected_status
        return {
            'name': 'status_code',
            'success': success,
            'message': f'HTTP Status code: {status_code} {"==" if success else "!="} {self.expected_status}',
        }


class ContentCheck:
    """Check if response content contains expected string."""
    def __init__(self, expected_content: str):
        self.expected_content = expected_content

    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        content = data.get('content', '')
        success = self.expected_content in content
        return {
            'name': 'content',
            'success': success,
            'message': f'HTTP Content {"contains" if success else "does not contain"} expected string',
        }


class HTTPMonitor(BaseMonitor):
    """Monitor for HTTP endpoints."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.url = config['url']
        self.method = config.get('method', 'GET')
        self.headers = config.get('headers', {})
        self.timeout = config.get('timeout', 10)
        self.verify_ssl = config.get('verify_ssl', True)
        
        # Optional request body for POST/PUT methods
        self.body = config.get('body')

    def _parse_condition(self, condition: str) -> Optional[Check]:
        """Parse condition string into a Check instance."""
        parts = condition.split()
        
        if len(parts) < 3:
            return None
            
        check_type = parts[0].lower()
        operator = parts[1]
        value = ' '.join(parts[2:])  # Join remaining parts for content checks
        
        if check_type == 'response_time' and operator == '<=':
            try:
                max_time = float(value.rstrip('s'))  # Remove 's' suffix if present
                return ResponseTimeCheck(max_time)
            except ValueError:
                return None
                
        elif check_type == 'status_code' and operator == '==':
            try:
                status = int(value)
                return StatusCodeCheck(status)
            except ValueError:
                return None
                
        elif check_type == 'content' and operator == 'contains':
            return ContentCheck(value)
            
        return None

    async def gather_data(self) -> Dict[str, Any]:
        """Gather HTTP response data."""
        start_time = datetime.now()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=self.method,
                    url=self.url,
                    headers=self.headers,
                    json=self.body if self.method in ['POST', 'PUT'] else None,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=None if not self.verify_ssl else True
                ) as response:
                    content = await response.text()
                    end_time = datetime.now()
                    response_time = (end_time - start_time).total_seconds()
                    
                    return {
                        'status_code': response.status,
                        'content': content,
                        'response_time': response_time,
                        'headers': dict(response.headers),
                    }
                    
        except asyncio.TimeoutError:
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds()
            raise Exception(f'Request timed out after {response_time:.2f}s')
            
        except Exception as e:
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds()
            raise Exception(f'Request failed: {str(e)}')

    def get_relevant_data_keys(self, check_name: str) -> List[str]:
        """Get relevant data keys for each check type."""
        if check_name == 'response_time':
            return ['response_time']
        elif check_name == 'status_code':
            return ['status_code']
        elif check_name == 'content':
            return ['content']
        else:
            return super().get_relevant_data_keys(check_name)
