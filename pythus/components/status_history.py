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
        Returns a structure optimized for the Highcharts heatmap.
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
            data["timePoints"].append(current_time.strftime("%H:%M"))
            current_time += timedelta(minutes=5)

        # Process each monitor's history
        for monitor in monitors:
            monitor_name = monitor.get("name", "Unknown")
            data["monitors"].append(monitor_name)
            
            history = monitor.get("history", {})
            monitor_data = []
            
            for time_point in data["timePoints"]:
                status = history.get(time_point, "unknown")
                # Convert status to numeric value for heatmap
                value = 2 if status == "success" else (0 if status == "error" else 1)
                monitor_data.append(value)
                
            data["statusData"].append(monitor_data)
            
        return data
