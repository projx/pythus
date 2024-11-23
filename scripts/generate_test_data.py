#!/usr/bin/env python3

import sys
import os
from datetime import datetime, timedelta
import random
import yaml

# Add the parent directory to the Python path so we can import pythus modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pythus.database import init_db, DatabaseManager, Monitor

def load_config():
    """Load monitor configuration from config.yaml."""
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    return config.get('endpoints', [])

def generate_test_data():
    """Generate test data for the last 24 hours."""
    # Initialize database
    Session = init_db()
    db_manager = DatabaseManager(Session)
    
    # Load monitor configurations
    monitors = load_config()
    
    # Current time and 24 hours ago
    now = datetime.now()
    start_time = now - timedelta(hours=24)
    
    # Success probability for each monitor (can be adjusted)
    monitor_success_rates = {
        'google': 0.99,
        'github': 0.95,
        'google-search': 0.98,
        'github-api': 0.97,
        'local-network': 0.90,
        'example-ssl': 0.85
    }
    
    # Generate data for each monitor
    for monitor_config in monitors:
        name = monitor_config['name']
        group = monitor_config.get('group', 'Default')
        url = monitor_config['url']
        interval = monitor_config.get('interval', '1m')
        
        # Convert interval to minutes
        if interval.endswith('s'):
            interval_minutes = int(interval[:-1]) / 60
        elif interval.endswith('m'):
            interval_minutes = int(interval[:-1])
        elif interval.endswith('h'):
            interval_minutes = int(interval[:-1]) * 60
        else:
            interval_minutes = 1
        
        # Get or create monitor in database
        monitor_id = db_manager.get_or_create_monitor(
            name=name,
            group=group,
            url=url,
            config=monitor_config
        )
        
        # Generate data points
        current_time = start_time
        while current_time <= now:
            # Determine success based on probability
            success_rate = monitor_success_rates.get(name, 0.95)
            success = random.random() < success_rate
            
            # Generate response time (faster when successful)
            if success:
                response_time = random.uniform(50, 500)
            else:
                response_time = random.uniform(500, 2000)
            
            # Add check result
            message = "Check successful" if success else "Response time exceeded threshold"
            details = {
                "status": 200 if success else 503,
                "response_time": response_time
            }
            
            if 'CERTIFICATE_EXPIRATION' in str(monitor_config.get('conditions', [])):
                # Add SSL details for monitors that check certificates
                details["ssl"] = {
                    "expires_in": "720h" if success else "24h",
                    "valid": success
                }
            
            # Add the check result
            db_manager.add_check_result(
                monitor_id=monitor_id,
                check_type='http_status',
                success=success,
                message=message,
                details=details
            )
            
            # Add response time
            db_manager.add_response_time(
                monitor_id=monitor_id,
                response_time=response_time
            )
            
            # Add log entry
            level = 'INFO' if success else 'ERROR'
            db_manager.add_log(
                monitor_id=monitor_id,
                level=level,
                message=message,
                details=details
            )
            
            # Move to next interval
            # Add some randomness to avoid perfectly regular intervals
            jitter = random.uniform(-0.1, 0.1) * interval_minutes
            current_time += timedelta(minutes=interval_minutes + jitter)

if __name__ == '__main__':
    print("Generating test data for the last 24 hours...")
    generate_test_data()
    print("Done!")
