from typing import Dict, List, Optional
from datetime import datetime, timedelta
from fastapi import Request
from fastapi.templating import Jinja2Templates

class StatusHistoryComponent:
    def __init__(self, templates: Jinja2Templates):
        self.templates = templates
        
    async def render(self, request: Request, monitors: List[Dict]) -> str:
        """Render the status history component."""
        return self.templates.get_template("components/status_history.html").render(
            request=request,
            monitors=monitors
        )

    @staticmethod
    def prepare_history_data(monitors: List[Dict]) -> Dict:
        """
        Prepare monitor history data for the frontend visualization.
        Returns a structure optimized for the eCharts heatmap.
        """
        now = datetime.now()
        six_hours_ago = now - timedelta(hours=6)
        
        # Initialize the data structure
        data = {
            "monitors": [],
            "timePoints": [],
            "statusData": []
        }
        
        # Generate time points for the last 6 hours in 5-minute intervals
        current_time = six_hours_ago
        while current_time <= now:
            is_hour = current_time.minute == 0
            data["timePoints"].append({
                "time": current_time.strftime("%H:%M"),
                "isHour": is_hour
            })
            current_time += timedelta(minutes=5)

        # Process each monitor's history
        for monitor in monitors:
            monitor_data = {
                "name": monitor.get("name", "Unknown"),
                "type": monitor.get("config", {}).get("type", "http"),
                "group": monitor.get("config", {}).get("group", "Default")
            }
            data["monitors"].append(monitor_data)
            
            # Get monitor history
            history = monitor.get("checks", [])
            status_data = []
            
            # Create a map of timestamps to status
            status_map = {}
            for check in history:
                try:
                    check_time = datetime.fromisoformat(check["timestamp"])
                    if six_hours_ago <= check_time <= now:
                        time_key = check_time.strftime("%H:%M")
                        status_map[time_key] = 2 if check.get("success", False) else 0
                except (ValueError, KeyError):
                    continue
            
            # Fill in status data for each time point
            for time_point in data["timePoints"]:
                status = status_map.get(time_point["time"], 1)  # 1 is unknown/no data
                status_data.append(status)
                
            data["statusData"].append(status_data)
            
        return data
