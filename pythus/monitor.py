"""Monitor system for checking various services."""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
from .monitors import MONITOR_TYPES
from .database import db_manager
import pickle
import cloudpickle

logger = logging.getLogger(__name__)

from typing import Dict, Any, List, Optional, Protocol
import aiohttp
import asyncio
import time
import dns.resolver
import ssl
import re
import socket
import concurrent.futures
import functools
import signal
from concurrent.futures import ProcessPoolExecutor
from abc import ABC, abstractmethod
from .config import Config

# Process timeout handler
def timeout_handler(signum, frame):
    raise TimeoutError("Monitor check process timed out")

# Function to run in separate process
def run_monitor_check_in_process(monitor_serialized):
    """Run a monitor check in a process with timeout."""
    # Set up process timeout handler
    import signal
    import asyncio
    import socket
    import ssl
    from datetime import datetime
    
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(20)  # 20 second timeout
    
    try:
        # Deserialize the monitor
        monitor = cloudpickle.loads(monitor_serialized)
        
        # Create new event loop for the process
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run the check
        result = loop.run_until_complete(monitor.run_checks())
        loop.close()
        
        # Clear the alarm
        signal.alarm(0)
        return result
    finally:
        signal.alarm(0)  # Make sure to clear the alarm even if there's an error

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
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.checks: List[Check] = []
        self.last_check_time = None
        self.last_check_result = None
        self.history = {}  # Store historical check results
        self.db_id = config.get('db_id')
        
        # Use interval directly from config
        self.interval = config['interval']
        
        # Initialize history with empty data for the last 6 hours
        self._init_history()
    
    def _init_history(self):
        """Initialize history with empty data for the last 6 hours."""
        now = datetime.now()
        for hour in range(6):
            hour_time = now - timedelta(hours=hour)
            for minute in range(0, 60, 5):
                time_key = f"{hour_time.hour:02d}:{minute:02d}"
                if time_key not in self.history:
                    self.history[time_key] = 'unknown'
    
    def _update_history(self, success: bool):
        """Update history with the latest check result."""
        now = datetime.now()
        # Round down to nearest 5 minutes
        minute = (now.minute // 5) * 5
        time_key = f"{now.hour:02d}:{minute:02d}"
        self.history[time_key] = 'success' if success else 'error'
        
        # Clean up old entries
        six_hours_ago = now - timedelta(hours=6)
        for hour in range(24):  # Check all possible hours
            for minute in range(0, 60, 5):
                time_key = f"{hour:02d}:{minute:02d}"
                if time_key in self.history:
                    try:
                        check_time = datetime.strptime(f"{now.date()} {time_key}", "%Y-%m-%d %H:%M")
                        if check_time < six_hours_ago:
                            del self.history[time_key]
                    except ValueError:
                        continue

    async def run_checks(self) -> Dict[str, Any]:
        """Run all checks for this monitor."""
        try:
            data = await self.gather_data()
            results = []
            all_success = True
            
            for check in self.checks:
                try:
                    result = await check.execute(data)
                    # Only store relevant data for each check type
                    if result.get('name') == 'dns_response':
                        result['details'] = {
                            'rcode': data.get('dns_rcode'),
                            'answers': data.get('answers', [])
                        }
                    elif result.get('name') == 'response_time':
                        result['details'] = {
                            'response_time': data.get('response_time')
                        }
                    else:
                        result['details'] = data
                    
                    results.append(result)
                    if not result.get('success', False):
                        all_success = False
                    
                    # Store check result in database
                    if self.db_id:
                        db_manager.add_check_result(
                            monitor_id=self.db_id,
                            check_type=result.get('name', 'unknown'),
                            success=result.get('success', False),
                            message=result.get('message', ''),
                            details=result.get('details', {})
                        )
                        
                        # Store response time if available
                        if 'response_time' in data:
                            db_manager.add_response_time(
                                monitor_id=self.db_id,
                                response_time=data['response_time']
                            )
                except Exception as e:
                    results.append({
                        'name': check.__class__.__name__,
                        'success': False,
                        'message': str(e),
                        'details': {'error': str(e)}
                    })
                    all_success = False
            
            self._update_history(all_success)
            self.last_check_result = {
                'success': all_success,
                'results': results,
                'raw_data': data,
                'timestamp': datetime.now().isoformat()
            }
            return self.last_check_result
            
        except Exception as e:
            self._update_history(False)
            error_result = {
                'success': False,
                'results': [{
                    'name': 'error',
                    'success': False,
                    'message': str(e),
                    'details': {'error': str(e)}
                }],
                'raw_data': {'error': str(e)},
                'timestamp': datetime.now().isoformat()
            }
            
            # Store error in database
            if self.db_id:
                db_manager.add_check_result(
                    monitor_id=self.db_id,
                    check_type='error',
                    success=False,
                    message=str(e),
                    details={'error': str(e)}
                )
            
            self.last_check_result = error_result
            return error_result

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
        if not self.last_check_result or 'results' not in self.last_check_result:
            return None
            
        for check in self.last_check_result['results']:
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
        for result in reversed(self.history.items()):
            if 'results' in result:
                for check in result['results']:
                    if check['name'] == test_name:
                        history.append({
                            'timestamp': result['timestamp'],
                            **check
                        })
                        break
        return history


class HTTPMonitor(BaseMonitor):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config['name'], config)
        
        # Add checks based on configuration
        if 'expected_status_code' in config:
            self.checks.append(HTTPStatusCheck(expected_status=config['expected_status_code']))
        
        if 'max_response_time_ms' in config:
            self.checks.append(ResponseTimeCheck(max_ms=config['max_response_time_ms']))
        
        if 'expected_content' in config:
            self.checks.append(ContentCheck(
                expected_content=config['expected_content'],
                is_regex=config.get('content_is_regex', False)
            ))
        
        if 'https' in config['url'].lower():
            if 'min_ssl_validity_days' in config:
                self.checks.append(SSLCheck(
                    min_days_valid=config['min_ssl_validity_days']
                ))
            else:
                self.checks.append(SSLCheck(
                    min_days_valid=30
                ))

    async def gather_data(self) -> Dict[str, Any]:
        start_time = time.time()
        ssl_context = ssl.create_default_context()
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        
        # Add timeout to HTTP requests
        timeout = aiohttp.ClientTimeout(total=20)  # 20 second total timeout
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
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
        super().__init__(config['name'], config)
        self.checks.append(DNSResponseCheck(
            expected_rcode=config.get('expected_rcode', 'NOERROR')
        ))
        if 'max_response_time_ms' in config:
            self.checks.append(ResponseTimeCheck(max_ms=config['max_response_time_ms']))
        elif 'max_response_time' in config:  # For backward compatibility
            self.checks.append(ResponseTimeCheck(max_ms=config['max_response_time']))

    async def gather_data(self) -> Dict[str, Any]:
        """Gather DNS query data."""
        if 'dns' not in self.config:
            raise ValueError("DNS configuration missing - ensure 'query_name' and 'query_type' are specified")
        
        start_time = time.time()
        try:
            # Create resolver with timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = 20  # 20 second timeout
            resolver.lifetime = 20  # 20 second total timeout
            
            # Get query parameters
            query_name = self.config['dns'].get('query_name', '')
            query_type = self.config['dns'].get('query_type', 'A')
            
            # Extract nameserver from URL
            nameserver = self.config['url']
            if '//' in nameserver:
                nameserver = nameserver.split('//')[1]
            if ':' in nameserver:  # Handle port if specified
                nameserver = nameserver.split(':')[0]
            
            resolver.nameservers = [nameserver]
            
            answers = resolver.resolve(
                query_name,
                query_type
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
        self.process_pool = ProcessPoolExecutor(max_workers=5)  # Reduce max workers to prevent overload
        self._shutdown = False

    def add_monitor(self, name: str, config: Dict[str, Any]) -> BaseMonitor:
        """Add a new monitor."""
        if config.get('type') == 'dns':
            monitor = DNSMonitor(config)
        else:
            monitor = HTTPMonitor(config)
        
        print(f"Created monitor {name} with {len(monitor.checks)} checks:")
        for check in monitor.checks:
            print(f"  - {check.__class__.__name__}")
        
        self.monitors[name] = monitor
        return monitor

    async def run_checks(self) -> Dict[str, Any]:
        """Run all monitor checks concurrently."""
        if self._shutdown:
            return {}

        now = time.time()
        tasks = []
        monitor_names = []
        
        # Only run checks for monitors that are due based on their interval
        for name, monitor in self.monitors.items():
            if monitor.last_check_time is None or (now - monitor.last_check_time) >= self._parse_interval(monitor.interval):
                print(f"Running check for monitor: {name} (interval: {monitor.interval})")
                task = self._run_monitor_check(name, monitor)
                tasks.append(task)
                monitor_names.append(name)
        
        if tasks:
            try:
                # Set a timeout for the entire batch of checks
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=30  # 30 second timeout for all checks
                )
                return {name: result for name, result in zip(monitor_names, results) 
                       if not isinstance(result, Exception)}
            except asyncio.TimeoutError:
                print("Batch check timeout - some monitors did not complete in time")
                return {}
        return {}

    def _parse_interval(self, interval: str) -> int:
        """Parse interval string (e.g., '1m', '30s') into seconds."""
        if interval.endswith('s'):
            return int(interval[:-1])
        elif interval.endswith('m'):
            return int(interval[:-1]) * 60
        elif interval.endswith('h'):
            return int(interval[:-1]) * 3600
        else:
            return 300  # Default to 5 minutes if format is unknown

    async def _run_monitor_check(self, name: str, monitor: BaseMonitor) -> Dict[str, Any]:
        """Run a single monitor check and handle the result."""
        try:
            monitor.last_check_time = time.time()
            
            try:
                # Run the check in a separate process with timeout
                loop = asyncio.get_event_loop()
                # Serialize the monitor
                monitor_serialized = cloudpickle.dumps(monitor)
                # Set a timeout for the individual check
                result = await asyncio.wait_for(
                    loop.run_in_executor(
                        self.process_pool,
                        run_monitor_check_in_process,
                        monitor_serialized
                    ),
                    timeout=20  # 20 second timeout per check
                )
                
                monitor.last_check_result = result
                success = result.get('success', False)
                print(f"Check completed for {name}: {'Success' if success else 'Failed'}")
                return result
            except asyncio.TimeoutError:
                print(f"Monitor {name} process timed out")
                # Log the timeout event
                if monitor.db_id:
                    db_manager.add_log(
                        monitor_id=monitor.db_id,
                        level='ERROR',
                        message=f'Monitor process timed out after 20 seconds',
                        details={
                            'error_type': 'process_timeout',
                            'monitor_name': name,
                            'timestamp': datetime.now().isoformat()
                        }
                    )
                return {
                    'success': False,
                    'error': 'Monitor check process timed out',
                    'raw_data': {'error': 'Process Timeout'}
                }
            except Exception as e:
                print(f"Monitor {name} process error: {e}")
                # Log any other process errors
                if monitor.db_id:
                    db_manager.add_log(
                        monitor_id=monitor.db_id,
                        level='ERROR',
                        message=f'Monitor process error: {str(e)}',
                        details={
                            'error_type': 'process_error',
                            'monitor_name': name,
                            'error': str(e),
                            'timestamp': datetime.now().isoformat()
                        }
                    )
                return {
                    'success': False,
                    'error': f'Monitor check process error: {str(e)}',
                    'raw_data': {'error': str(e)}
                }
        except Exception as e:
            print(f"Error running check for {name}: {e}")
            # Log any unexpected errors
            if monitor.db_id:
                db_manager.add_log(
                    monitor_id=monitor.db_id,
                    level='ERROR',
                    message=f'Unexpected error in monitor check: {str(e)}',
                    details={
                        'error_type': 'unexpected_error',
                        'monitor_name': name,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    }
                )
            return {
                'success': False,
                'error': str(e),
                'raw_data': {'error': str(e)}
            }

    def shutdown(self):
        """Shutdown the monitor manager and cleanup resources."""
        self._shutdown = True
        if hasattr(self, 'process_pool'):
            try:
                # Cancel any pending tasks
                loop = asyncio.get_event_loop()
                for task in asyncio.all_tasks(loop):
                    task.cancel()
                
                # Shutdown the process pool and wait for processes to finish
                self.process_pool.shutdown(wait=True, cancel_futures=True)
            except Exception as e:
                print(f"Error during shutdown: {e}")
            finally:
                self.process_pool = None

    def __del__(self):
        """Clean up process pool on deletion."""
        self.shutdown()


class MonitorSystem:
    """System for managing and running monitors."""
    
    def __init__(self, config):
        self.config = config
        self.monitors = {}
        self.initialize_monitors()
        
    def initialize_monitors(self):
        """Initialize monitors from configuration."""
        for monitor_config in self.config.monitors:
            try:
                monitor_type = monitor_config.type
                monitor_class = MONITOR_TYPES.get(monitor_type)
                
                if not monitor_class:
                    logger.error(f"Unknown monitor type: {monitor_type}")
                    continue
                    
                monitor = monitor_class(
                    name=monitor_config.name,
                    config=monitor_config.dict()
                )
                self.monitors[monitor_config.name] = monitor
                
            except Exception as e:
                logger.error(f"Failed to initialize monitor {monitor_config.name}: {str(e)}")
                
    async def run_monitor(self, monitor_name: str) -> Optional[Dict[str, Any]]:
        """Run a specific monitor by name."""
        monitor = self.monitors.get(monitor_name)
        if not monitor:
            return None
            
        try:
            result = await monitor.run_checks()
            return result
        except Exception as e:
            logger.error(f"Error running monitor {monitor_name}: {str(e)}")
            return None
            
    async def run_all_monitors(self) -> Dict[str, Dict[str, Any]]:
        """Run all monitors and return their results."""
        results = {}
        for name, monitor in self.monitors.items():
            try:
                result = await monitor.run_checks()
                results[name] = result
            except Exception as e:
                logger.error(f"Error running monitor {name}: {str(e)}")
                results[name] = {
                    'success': False,
                    'error': str(e)
                }
        return results
        
    def get_monitor_history(self, monitor_name: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get historical results for a specific monitor."""
        monitor = self.monitors.get(monitor_name)
        if not monitor:
            return []
            
        return db_manager.get_monitor_history(monitor.db_id, limit)
        
    def get_monitor_status(self, monitor_name: str) -> Optional[Dict[str, Any]]:
        """Get current status of a specific monitor."""
        monitor = self.monitors.get(monitor_name)
        if not monitor:
            return None
            
        return {
            'name': monitor_name,
            'type': monitor.config['type'],
            'last_check': monitor.last_check_result,
            'history': monitor.history
        }
        
    def get_all_monitor_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Get current status of all monitors."""
        return {
            name: self.get_monitor_status(name)
            for name in self.monitors
        }
