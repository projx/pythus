import uvicorn
import os
import sys
from pathlib import Path

def main():
    # Ensure templates directory is in the correct location
    templates_dir = Path(__file__).parent / "templates"
    if not templates_dir.exists():
        print(f"Error: Templates directory not found at {templates_dir}")
        sys.exit(1)

    port = 8081  # Changed port to avoid conflicts
    print(f"\nStarting Pythus on http://localhost:{port}")
    print("Press CTRL+C to stop the server\n")

    # Start the FastAPI application
    uvicorn.run(
        "pythus.web:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info"
    )

if __name__ == "__main__":
    main()
