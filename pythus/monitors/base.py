from typing import Dict, Any, List, Optional, Protocol
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from ..database import db_manager


class Check(Protocol):
    """Protocol for all check implementations."""
    async def execute(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the check and return results."""
        ...


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
        
        # Initialize checks based on conditions
        self._init_checks()

    def _init_history(self):
        """Initialize history with empty data for the last 6 hours."""
        now = datetime.now()
        six_hours_ago = now - timedelta(hours=6)
        
        # Create time slots every 5 minutes
        current = six_hours_ago
        while current <= now:
            time_key = current.strftime("%H:%M")
            if time_key not in self.history:
                self.history[time_key] = None
            current += timedelta(minutes=5)
        
        # Clean up old entries
        for time_key in list(self.history.keys()):
            if time_key in self.history:
                try:
                    check_time = datetime.strptime(f"{now.date()} {time_key}", "%Y-%m-%d %H:%M")
                    if check_time < six_hours_ago:
                        del self.history[time_key]
                except ValueError:
                    continue

    def _init_checks(self):
        """Initialize checks based on conditions in config."""
        for condition in self.config.get('conditions', []):
            check = self._parse_condition(condition)
            if check:
                self.checks.append(check)

    @abstractmethod
    def _parse_condition(self, condition: str) -> Optional[Check]:
        """Parse a condition string and return appropriate Check instance."""
        pass

    @abstractmethod
    async def gather_data(self) -> Dict[str, Any]:
        """Gather raw data for checks to evaluate."""
        pass

    async def run_checks(self) -> Dict[str, Any]:
        """Run all checks for this monitor."""
        try:
            data = await self.gather_data()
            results = []
            all_success = True
            
            for check in self.checks:
                result = await check.execute(data)
                # Store only relevant data for each check
                result['details'] = {
                    k: v for k, v in data.items() 
                    if k in self.get_relevant_data_keys(result.get('name', ''))
                }
                
                # Add target info to the message
                target_info = f" [{self.name}]"
                if hasattr(self, 'url'):
                    target_info += f" URL: {self.url}"
                elif hasattr(self, 'domain'):
                    target_info += f" Domain: {self.domain}"
                    if hasattr(self, 'record_type'):
                        target_info += f" ({self.record_type})"
                
                result['message'] = f"{result['message']}{target_info}"
                results.append(result)
                if not result.get('success', False):
                    all_success = False
                
                # Store check result in database
                db_manager.add_check_result(
                    monitor_id=self.db_id,
                    check_type=result.get('name', 'unknown'),
                    success=result.get('success', False),
                    message=result.get('message', ''),
                    details=result.get('details', {})
                )
                
                # Add log entry for the check
                level = 'INFO' if result.get('success', False) else 'ERROR'
                db_manager.add_log(
                    monitor_id=self.db_id,
                    level=level,
                    message=result.get('message', ''),
                    details=result.get('details', {})
                )
                    
                # Store response time if available
                if 'response_time' in data:
                    db_manager.add_response_time(
                        monitor_id=self.db_id,
                        response_time=data['response_time']
                    )
            
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
            # Add target info to error message
            target_info = f" [{self.name}]"
            if hasattr(self, 'url'):
                target_info += f" URL: {self.url}"
            elif hasattr(self, 'domain'):
                target_info += f" Domain: {self.domain}"
                if hasattr(self, 'record_type'):
                    target_info += f" ({self.record_type})"
            
            error_message = f"{str(e)}{target_info}"
            error_result = {
                'success': False,
                'results': [{
                    'name': 'error',
                    'success': False,
                    'message': error_message,
                    'details': {'error': error_message}
                }],
                'raw_data': {'error': error_message},
                'timestamp': datetime.now().isoformat()
            }
            
            # Store error in database
            db_manager.add_check_result(
                monitor_id=self.db_id,
                check_type='error',
                success=False,
                message=error_message,
                details={'error': error_message}
            )
            
            # Add error log entry
            db_manager.add_log(
                monitor_id=self.db_id,
                level='ERROR',
                message=error_message,
                details={'error': error_message}
            )
            
            self.last_check_result = error_result
            return error_result

    def _update_history(self, success: bool):
        """Update history with the latest check result."""
        time_key = datetime.now().strftime("%H:%M")
        self.history[time_key] = success
        self._init_history()  # Clean up old entries

    def get_result(self, test_name: str) -> Optional[Dict[str, Any]]:
        """Get the most recent result for a specific test."""
        if not self.last_check_result or 'results' not in self.last_check_result:
            return None
            
        for result in self.last_check_result['results']:
            if result.get('name') == test_name:
                return result
        return None

    def get_result_history(self, test_name: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get historical results for a specific test."""
        return db_manager.get_check_history(self.db_id, test_name, limit)

    def get_relevant_data_keys(self, check_name: str) -> List[str]:
        """Get list of relevant data keys for a specific check type."""
        return ['response_time']  # Base implementation, override in subclasses
