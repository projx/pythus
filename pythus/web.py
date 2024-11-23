from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.requests import Request
import asyncio
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from .config import Config
from .monitor import MonitorManager
from .database import init_db, DatabaseManager
from .components.status_history import StatusHistoryComponent

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
status_history = StatusHistoryComponent(templates)

# Setup routes
@app.on_event("startup")
async def startup_event():
    global config, db_manager
    try:
        # Initialize database
        Session = init_db()
        db_manager = DatabaseManager(Session)
        
        # Load configuration
        config = Config.from_env()
        
        # Initialize monitors
        for monitor_config in config.monitors:
            # Add monitor to database
            monitor_id = db_manager.add_monitor(
                name=monitor_config.name,
                group=monitor_config.group or 'Default',
                url=monitor_config.url,
                config=monitor_config.dict()
            )
            
            # Add db_id to monitor config
            monitor_config_dict = monitor_config.dict()
            monitor_config_dict['db_id'] = monitor_id
            
            # Create and configure monitor
            monitor = monitor_manager.add_monitor(monitor_config.name, monitor_config_dict)
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
            
        # Wait a short time before checking again
        await asyncio.sleep(1)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render the dashboard."""
    monitors = []
    for name, monitor in monitor_manager.monitors.items():
        # Get latest checks from database (limit to 10 most recent)
        history = db_manager.get_monitor_history(monitor.db_id, limit=10)
        latest_checks = history['checks'][:5] if history and 'checks' in history else []
        
        monitor_data = {
            "name": name,
            "db_id": monitor.db_id,
            "config": monitor.config,
            "last_check": monitor.last_check_result or {},
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
            "monitors": monitors,
            "status_history": await status_history.render(request, monitors)
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


@app.get("/api/monitors")
async def get_monitors():
    """Get all monitors and their status."""
    monitors = []
    for name, monitor in monitor_manager.monitors.items():
        monitor_data = {
            'id': getattr(monitor, 'db_id', None),
            'name': name,
            'url': monitor.config['url'],
            'type': monitor.config.get('type', 'unknown'),
            'last_check': monitor.last_check_result or {},
            'history': monitor.history
        }
        monitors.append(monitor_data)
    return monitors


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
            "last_check": monitor.last_check_result or {},
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
        "last_check": monitor.last_check_result or {},
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


@app.get("/api/monitors/history")
async def get_monitor_history():
    """Get historical data for all monitors."""
    try:
        now = datetime.now()
        six_hours_ago = now - timedelta(hours=6)
        
        # Initialize time points (every 5 minutes for the last 6 hours)
        time_points = []
        current = six_hours_ago
        while current <= now:
            # Only include the hour label for full hours
            if current.minute == 0:
                time_points.append({"time": current.strftime("%H:%M"), "isHour": True})
            else:
                time_points.append({"time": current.strftime("%H:%M"), "isHour": False})
            current += timedelta(minutes=5)

        # Get monitor data
        monitors = []
        status_data = []
        
        for name, monitor in sorted(
            monitor_manager.monitors.items(),
            key=lambda x: (x[1].config.get('group', 'Default'), x[0])
        ):
            try:
                # Include monitor metadata
                monitors.append({
                    "name": name,
                    "type": monitor.config.get('type', 'http'),
                    "group": monitor.config.get('group', 'Default')
                })
                monitor_history = []
                
                # Get history from database with time range
                history = db_manager.get_monitor_history(monitor.db_id, six_hours_ago, now)
                if not history:
                    # If monitor has no history, fill with unknown status
                    monitor_history = [1] * len(time_points)  # 1 represents unknown status
                else:
                    checks = history.get('checks', [])
                    
                    # Create status map for quick lookup
                    status_map = {}
                    for check in checks:
                        try:
                            check_time = datetime.fromisoformat(check['timestamp'])
                            if six_hours_ago <= check_time <= now:
                                time_key = check_time.strftime("%H:%M")
                                status_map[time_key] = 2 if check.get('success', False) else 0
                        except (ValueError, KeyError) as e:
                            print(f"Error processing check for {name}: {e}")
                            continue

                    # Fill in status data for each time point
                    for time_point in time_points:
                        status = status_map.get(time_point["time"], 1)  # 1 is unknown/no data
                        monitor_history.append(status)
                        
                status_data.append(monitor_history)
            except Exception as e:
                print(f"Error processing monitor {name}: {e}")
                # Add empty history for failed monitor
                status_data.append([1] * len(time_points))
        
        result = {
            "monitors": monitors,
            "timePoints": time_points,
            "statusData": status_data
        }
        return result
    except Exception as e:
        print(f"Error in get_monitor_history: {e}")
        return {
            "monitors": [],
            "timePoints": [],
            "statusData": []
        }


@app.get("/logs", response_class=HTMLResponse)
async def logs(request: Request, page: int = 1):
    """Render the logs page."""
    per_page = 100
    logs_data = db_manager.get_logs(page=page, per_page=per_page)
    
    # Get monitor names for each log
    logs_with_monitors = []
    for log in logs_data['logs']:
        monitor = db_manager.get_monitor_by_id(log['monitor_id'])
        monitor_name = monitor['name'] if monitor else 'Unknown Monitor'
        logs_with_monitors.append({
            "log": log,
            "monitor_name": monitor_name
        })
    
    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "logs": logs_with_monitors,
            "total_pages": logs_data['total_pages'],
            "current_page": page,
            "has_next": page < logs_data['total_pages'],
            "has_prev": page > 1
        }
    )
