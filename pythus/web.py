from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.requests import Request
import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from .config import Config, Endpoint
from .monitor import MonitorManager
from .database import init_db, DatabaseManager

app = FastAPI(title="Pythus - Service Health Monitor")
templates = Jinja2Templates(directory="pythus/templates")

# Add datetime filter
def format_datetime(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            try:
                value = datetime.fromtimestamp(float(value))
            except (ValueError, TypeError):
                return value
    return value.strftime("%Y-%m-%d %H:%M:%S")

templates.env.filters["datetime"] = format_datetime

# Global state
monitor_manager = MonitorManager()
config: Config = None
db_manager: Optional[DatabaseManager] = None


@app.on_event("startup")
async def startup_event():
    global config, db_manager
    try:
        # Initialize database
        Session = init_db()
        db_manager = DatabaseManager(Session)
        
        # Load configuration
        config = Config.from_env()
        
        # Initialize monitors for each endpoint
        for endpoint in config.endpoints:
            # Create monitor config
            monitor_config = {
                'name': endpoint.name,
                'group': endpoint.group,
                'url': endpoint.url,
                'type': 'dns' if endpoint.dns else 'http'
            }
            
            # Add DNS configuration if present
            if endpoint.dns:
                monitor_config['dns'] = {
                    'query_name': endpoint.dns.query_name,
                    'query_type': endpoint.dns.query_type
                }
            
            # Add SSL checks to GitHub and Google HTTP monitors with a 30-day minimum validity requirement
            if endpoint.name == 'github-http' or endpoint.name == 'google-http':
                monitor_config['checks'] = {
                    'status': 200,
                    'max_response_time': 2000 if endpoint.name == 'github-http' else 1000,
                    'ssl': {
                        'min_days_valid': 30
                    }
                }
            
            # Add monitor to database
            monitor_id = db_manager.add_monitor(
                name=endpoint.name,
                group=endpoint.group,
                url=endpoint.url,
                config=monitor_config
            )
            
            # Create and configure monitor
            monitor = monitor_manager.add_monitor(endpoint.name, monitor_config)
            monitor.db_id = monitor_id  # Store database ID in monitor
            
        # Start background monitoring tasks
        asyncio.create_task(run_monitors())
    except Exception as e:
        print(f"Failed to start: {e}")


async def run_monitors():
    """Background task to run all monitors."""
    while True:
        try:
            results = await monitor_manager.run_checks()
            
            # Store results in database
            for name, result in results.items():
                monitor = monitor_manager.monitors[name]
                
                # Store response time
                if 'response_time' in result.get('raw_data', {}):
                    db_manager.add_response_time(
                        monitor.db_id,
                        result['raw_data']['response_time']
                    )
                
                # Store check results
                for check in result.get('checks', []):
                    db_manager.add_check_result(
                        monitor.db_id,
                        check['name'],
                        check['success'],
                        check['message'],
                        check.get('details')
                    )
                
                # Add log entry
                level = 'INFO' if result['success'] else 'ERROR'
                message = 'Check successful' if result['success'] else result.get('error', 'Check failed')
                db_manager.add_log(
                    monitor.db_id,
                    level,
                    message,
                    result.get('raw_data')
                )
                
        except Exception as e:
            print(f"Error running monitors: {e}")
        
        await asyncio.sleep(5)  # Check every 5 seconds


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render the dashboard."""
    monitors = []
    for name, monitor in monitor_manager.monitors.items():
        # Get latest checks from database
        history = db_manager.get_monitor_history(monitor.db_id)
        latest_checks = history['checks'][:5] if history and 'checks' in history else []
        
        monitor_data = {
            "name": name,
            "db_id": monitor.db_id,
            "config": monitor.config,
            "last_check": monitor.last_check,
            "checks": latest_checks
        }
        monitors.append(monitor_data)
    
    # Sort monitors by group and name
    monitors.sort(key=lambda m: (m['config'].get('group', 'Default'), m['name']))
    
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "Pythus - Service Health Monitor",
            "monitors": monitors
        }
    )


@app.get("/monitors/{monitor_id}", response_class=HTMLResponse)
async def monitor_detail(request: Request, monitor_id: int):
    """Render detailed view for a specific monitor."""
    # Get monitor history from database
    history = db_manager.get_monitor_history(monitor_id)
    if not history:
        raise HTTPException(status_code=404, detail="Monitor not found")
    
    # Get the monitor from the manager to access current state
    monitor = None
    for m in monitor_manager.monitors.values():
        if m.db_id == monitor_id:
            monitor = m
            break
    
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")
    
    # Prepare data for template
    monitor_data = {
        "name": history['monitor']['name'],
        "url": history['monitor']['url'],
        "group": history['monitor']['group'],
        "config": history['monitor']['config'],
        "db_id": history['monitor']['id']
    }
    
    return templates.TemplateResponse(
        "monitor_detail.html",
        {
            "request": request,
            "monitor": monitor_data,
            "checks": history['checks'],
            "response_times": history['response_times'],
            "logs": history['logs']
        }
    )


@app.get("/api/monitors/{monitor_id}/history")
async def get_monitor_history(
    monitor_id: int,
    start: Optional[str] = None,
    end: Optional[str] = None
):
    """Get historical data for a specific monitor."""
    try:
        start_time = datetime.fromisoformat(start) if start else None
        end_time = datetime.fromisoformat(end) if end else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid datetime format")
    
    history = db_manager.get_monitor_history(monitor_id, start_time, end_time)
    if not history:
        raise HTTPException(status_code=404, detail="Monitor not found")
    
    return history


@app.get("/api/endpoints")
async def get_endpoints():
    """Get all endpoints and their current status."""
    monitors = []
    for name, monitor in monitor_manager.monitors.items():
        # Get latest checks from database
        history = db_manager.get_monitor_history(monitor.db_id)
        latest_checks = history['checks'][:5] if history and 'checks' in history else []
        
        monitor_data = {
            "name": name,
            "id": monitor.db_id,  # Use db_id for consistent identification
            "config": monitor.config,
            "last_check": monitor.last_check,
            "checks": latest_checks
        }
        monitors.append(monitor_data)
    
    # Sort monitors by group and name
    monitors.sort(key=lambda m: (m['config'].get('group', 'Default'), m['name']))
    return monitors


@app.get("/api/endpoints/{name}")
async def get_endpoint(name: str):
    """Get current status for a specific endpoint."""
    if name not in monitor_manager.monitors:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    monitor = monitor_manager.monitors[name]
    return {
        "id": monitor.db_id,
        "name": name,
        "group": monitor.config.get('group', 'default'),
        "url": monitor.config.get('url', ''),
        "type": monitor.config.get('type', 'http'),
        "last_check": monitor.last_check,
        "config": monitor.config,
        "results": monitor.results
    }


@app.get("/api/endpoints/{name}/history")
async def get_endpoint_history(
    name: str,
    start: Optional[str] = None,
    end: Optional[str] = None
):
    """Get historical results for a specific endpoint."""
    if name not in monitor_manager.monitors:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    monitor = monitor_manager.monitors[name]
    
    try:
        start_time = datetime.fromisoformat(start) if start else None
        end_time = datetime.fromisoformat(end) if end else None
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid datetime format")
    
    history = db_manager.get_monitor_history(monitor.db_id, start_time, end_time)
    return {
        "id": monitor.db_id,
        "name": name,
        "group": monitor.config.get('group', 'default'),
        "url": monitor.config.get('url', ''),
        "type": monitor.config.get('type', 'http'),
        "history": history
    }
