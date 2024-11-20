from typing import Dict, Any, List, Optional, Protocol
import aiohttp
import asyncio
import time
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse
from abc import ABC, abstractmethod
from .config import Endpoint
import ssl
import socket


class Check(Protocol):
    """Protocol for all check implementations."""
    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the check and return results."""
        ...


class HTTPStatusCheck:
    """Check if HTTP status code matches expected value."""
    def __init__(self, expected_status: int = 200):
        self.expected_status = expected_status

    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        status = data.get('status')
        return {
            'name': 'http_status',
            'success': status == self.expected_status,
            'message': f'Expected status {self.expected_status}, got {status}'
        }


class SSLCheck:
    """Check SSL certificate validity."""
    def __init__(self, min_days_valid: int = 30):
        self.min_days_valid = min_days_valid

    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if 'ssl_error' in data:
            return {
                'name': 'ssl',
                'success': False,
                'message': data['ssl_error']
            }
        
        if 'certificate_expiration' not in data:
            return {
                'name': 'ssl',
                'success': False,
                'message': 'No SSL certificate found'
            }
        
        try:
            from datetime import datetime
            expiry = datetime.fromisoformat(data['certificate_expiration'])
            days_remaining = (expiry - datetime.now()).days
            
            return {
                'name': 'ssl',
                'success': days_remaining >= self.min_days_valid,
                'message': f'Certificate expires in {days_remaining} days'
            }
        except Exception as e:
            return {
                'name': 'ssl',
                'success': False,
                'message': f'Failed to parse certificate expiration: {str(e)}'
            }


class ResponseTimeCheck:
    """Check if response time is within acceptable range."""
    def __init__(self, max_ms: int):
        self.max_ms = max_ms

    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        response_time = data.get('response_time', float('inf'))
        return {
            'name': 'response_time',
            'success': response_time <= self.max_ms,
            'message': f'Response time {response_time:.2f}ms (max {self.max_ms}ms)'
        }


class ContentCheck:
    """Check if response content contains expected string or matches regex."""
    def __init__(self, expected_content: str, is_regex: bool = False):
        self.expected_content = expected_content
        self.is_regex = is_regex

    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        content = data.get('body', '')
        if self.is_regex:
            import re
            match = re.search(self.expected_content, content)
            return {
                'name': 'content',
                'success': bool(match),
                'message': f'{"Found" if match else "Did not find"} content matching regex'
            }
        else:
            found = self.expected_content in content
            return {
                'name': 'content',
                'success': found,
                'message': f'{"Found" if found else "Did not find"} expected content'
            }


class DNSResponseCheck:
    """Check if DNS response contains expected records."""
    def __init__(self, expected_rcode: str = 'NOERROR'):
        self.expected_rcode = expected_rcode

    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        rcode = data.get('dns_rcode')
        return {
            'name': 'dns_response',
            'success': rcode == self.expected_rcode,
            'message': f'DNS response code: {rcode}'
        }


class BaseMonitor(ABC):
    """Base class for all monitors."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config['name']  # Set name from config
        self.db_id = None  # Database ID for this monitor
        self.checks: List[Check] = []
        self.last_check: Dict[str, Any] = {}
        self.results: List[Dict[str, Any]] = []

    @abstractmethod
    async def gather_data(self) -> Dict[str, Any]:
        """Gather raw data for checks to evaluate."""
        pass

    def get_result(self, test_name: str) -> Optional[Dict[str, Any]]:
        """Get the most recent result for a specific test.
        
        Args:
            test_name: Name of the test to get results for (e.g., 'http_status', 'ssl', 'response_time')
            
        Returns:
            The most recent result for the specified test, or None if not found
        """
        if not self.last_check or 'checks' not in self.last_check:
            return None
            
        for check in self.last_check['checks']:
            if check['name'] == test_name:
                return check
        return None

    def get_result_history(self, test_name: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get historical results for a specific test.
        
        Args:
            test_name: Name of the test to get results for
            limit: Maximum number of historical results to return (default: 100)
            
        Returns:
            List of historical results for the specified test, newest first
        """
        history = []
        for result in reversed(self.results[-limit:]):
            if 'checks' in result:
                for check in result['checks']:
                    if check['name'] == test_name:
                        history.append({
                            'timestamp': result['timestamp'],
                            **check
                        })
                        break
        return history

    async def run_check(self) -> Dict[str, Any]:
        """Execute all checks and return combined results."""
        try:
            # Gather the raw data
            data = await self.gather_data()
            data['timestamp'] = datetime.utcnow().isoformat()
            
            # Run all checks
            check_results = []
            for check in self.checks:
                try:
                    result = await check.execute(data)
                    check_results.append(result)
                except Exception as e:
                    check_results.append({
                        'name': check.__class__.__name__,
                        'success': False,
                        'message': f'Check failed: {str(e)}'
                    })

            # Combine results
            result = {
                'timestamp': data['timestamp'],
                'success': all(r['success'] for r in check_results),
                'raw_data': data,
                'checks': check_results
            }
            
            self.add_result(result)
            return result
            
        except Exception as e:
            error_result = {
                'timestamp': datetime.utcnow().isoformat(),
                'success': False,
                'error': str(e),
                'checks': []
            }
            self.add_result(error_result)
            return error_result

    def add_result(self, result: Dict[str, Any]) -> None:
        """Add a result to the history and update last_check."""
        self.last_check = result
        self.results.append(result)
        if len(self.results) > 100:
            self.results.pop(0)


class HTTPMonitor(BaseMonitor):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Add checks based on configuration
        if 'expected_status' in config:
            self.checks.append(HTTPStatusCheck(expected_status=config['expected_status']))
        
        if 'max_response_time' in config:
            self.checks.append(ResponseTimeCheck(max_ms=config['max_response_time']))
        
        if 'expected_content' in config:
            self.checks.append(ContentCheck(
                expected_content=config['expected_content'],
                is_regex=config.get('content_is_regex', False)
            ))
        
        if 'https' in config['url'].lower():
            if 'min_ssl_days' in config:
                self.checks.append(SSLCheck(
                    min_days_valid=config['min_ssl_days']
                ))
            else:
                self.checks.append(SSLCheck(
                    min_days_valid=30
                ))

    async def gather_data(self) -> Dict[str, Any]:
        start_time = time.time()
        ssl_context = ssl.create_default_context()
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                async with session.get(self.config['url']) as response:
                    response_time = (time.time() - start_time) * 1000
                    body = await response.text()
                    
                    data = {
                        'status': response.status,
                        'response_time': response_time,
                        'body': body,
                    }
                    
                    # Only try to get SSL info for HTTPS URLs
                    if self.config['url'].lower().startswith('https://'):
                        try:
                            hostname = self.config['url'].split('//')[1].split('/')[0]
                            if ':' in hostname:
                                hostname = hostname.split(':')[0]
                            
                            with socket.create_connection((hostname, 443)) as sock:
                                with ssl_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                                    cert = ssock.getpeercert()
                                    if cert:
                                        data['certificate_info'] = {
                                            'subject': dict(x[0] for x in cert['subject']),
                                            'issuer': dict(x[0] for x in cert['issuer']),
                                            'version': cert.get('version', None),
                                            'serialNumber': cert.get('serialNumber', None),
                                            'notBefore': cert.get('notBefore', None),
                                            'notAfter': cert.get('notAfter', None)
                                        }
                                        # Format the expiration date in ISO format
                                        if cert.get('notAfter'):
                                            from datetime import datetime
                                            expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                                            data['certificate_expiration'] = expiry.isoformat()
                        except Exception as e:
                            data['ssl_error'] = f"Failed to get SSL certificate: {str(e)}"
                    
                    return data
            except aiohttp.ClientError as e:
                return {
                    'status': 0,
                    'response_time': (time.time() - start_time) * 1000,
                    'error': str(e),
                    'body': ''
                }


class DNSMonitor(BaseMonitor):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.checks.append(DNSResponseCheck(
            expected_rcode=config.get('expected_rcode', 'NOERROR')
        ))
        if 'max_response_time' in config:
            self.checks.append(ResponseTimeCheck(max_ms=config['max_response_time']))

    async def gather_data(self) -> Dict[str, Any]:
        """Gather DNS query data."""
        if 'dns' not in self.config:
            raise ValueError("DNS configuration missing - ensure 'query_name' and 'query_type' are specified")
        
        start_time = time.time()
        resolver = dns.resolver.Resolver()
        
        # Extract nameserver from URL
        nameserver = self.config['url']
        if '//' in nameserver:
            nameserver = nameserver.split('//')[1]
        if ':' in nameserver:  # Handle port if specified
            nameserver = nameserver.split(':')[0]
        
        resolver.nameservers = [nameserver]
        
        try:
            answers = resolver.resolve(
                self.config['dns']['query_name'],
                self.config['dns']['query_type']
            )
            response_time = (time.time() - start_time) * 1000
            
            return {
                'dns_rcode': 'NOERROR',
                'response_time': response_time,
                'answers': [str(rdata) for rdata in answers]
            }
        except dns.resolver.NXDOMAIN:
            return {
                'dns_rcode': 'NXDOMAIN',
                'response_time': (time.time() - start_time) * 1000,
                'answers': []
            }
        except dns.resolver.NoAnswer:
            return {
                'dns_rcode': 'NOERROR',
                'response_time': (time.time() - start_time) * 1000,
                'answers': []
            }
        except dns.resolver.NoNameservers:
            return {
                'dns_rcode': 'SERVFAIL',
                'response_time': (time.time() - start_time) * 1000,
                'error': 'No nameservers could be reached',
                'answers': []
            }
        except Exception as e:
            return {
                'dns_rcode': 'ERROR',
                'response_time': (time.time() - start_time) * 1000,
                'error': str(e),
                'answers': []
            }


class MonitorManager:
    """Manages all monitors."""
    
    def __init__(self):
        self.monitors: Dict[str, BaseMonitor] = {}

    def add_monitor(self, name: str, config: Dict[str, Any]) -> BaseMonitor:
        """Add a new monitor."""
        if config['type'].lower() == 'http':
            monitor = HTTPMonitor(config)
        elif config['type'].lower() == 'dns':
            monitor = DNSMonitor(config)
        else:
            raise ValueError(f"Unknown monitor type: {config['type']}")
            
        self.monitors[name] = monitor
        return monitor

    async def run_checks(self) -> Dict[str, Dict[str, Any]]:
        """Run all monitor checks concurrently."""
        tasks = []
        for name, monitor in self.monitors.items():
            tasks.append(self._run_monitor_check(name, monitor))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {name: result for name, result in zip(self.monitors.keys(), results)}
    
    async def _run_monitor_check(self, name: str, monitor: BaseMonitor) -> Dict[str, Any]:
        """Run a single monitor check and handle the result."""
        return await monitor.run_check()
