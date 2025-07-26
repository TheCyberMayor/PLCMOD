#!/usr/bin/env python3
"""
Script to start both the ICS Cybersecurity API and Dashboard services.
This script runs them as separate processes to avoid WSGI/ASGI conflicts.
"""

import subprocess
import sys
import time
import signal
import os
from pathlib import Path

def start_api():
    """Start the FastAPI service."""
    print("Starting ICS Cybersecurity API...")
    api_process = subprocess.Popen([
        sys.executable, "main.py"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return api_process

def start_dashboard():
    """Start the Dash dashboard service."""
    print("Starting ICS Cybersecurity Dashboard...")
    dashboard_process = subprocess.Popen([
        sys.executable, "src/dashboard/app.py"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return dashboard_process

def main():
    """Main function to start both services."""
    print("ICS Cybersecurity System - Service Starter")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("main.py").exists():
        print("Error: main.py not found. Please run this script from the project root directory.")
        sys.exit(1)
    
    api_process = None
    dashboard_process = None
    
    try:
        # Start API
        api_process = start_api()
        print(f"API process started with PID: {api_process.pid}")
        
        # Wait a moment for API to start
        time.sleep(3)
        
        # Start Dashboard
        dashboard_process = start_dashboard()
        print(f"Dashboard process started with PID: {dashboard_process.pid}")
        
        print("\n" + "=" * 50)
        print("Services are starting...")
        print("API will be available at: http://0.0.0.0:8000")
        print("Dashboard will be available at: http://0.0.0.0:8050")
        print("Press Ctrl+C to stop all services")
        print("=" * 50)
        
        # Keep the script running
        while True:
            time.sleep(1)
            
            # Check if processes are still running
            if api_process and api_process.poll() is not None:
                print("Warning: API process has stopped")
                break
                
            if dashboard_process and dashboard_process.poll() is not None:
                print("Warning: Dashboard process has stopped")
                break
                
    except KeyboardInterrupt:
        print("\nShutting down services...")
        
    finally:
        # Clean up processes
        if api_process:
            print("Stopping API process...")
            api_process.terminate()
            try:
                api_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                api_process.kill()
        
        if dashboard_process:
            print("Stopping Dashboard process...")
            dashboard_process.terminate()
            try:
                dashboard_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dashboard_process.kill()
        
        print("All services stopped.")

if __name__ == "__main__":
    main() 