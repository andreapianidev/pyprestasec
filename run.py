#!/usr/bin/env python3
"""
PyPrestaSec Launcher Script
Easy way to start the vulnerability scanner
"""

import subprocess
import sys
import os

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import streamlit
        import requests
        import bs4
        import packaging
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("\n📦 Please install dependencies:")
        print("   pip install -r requirements.txt")
        return False

def main():
    """Main launcher function"""
    print("🛡️ PyPrestaSec - PrestaShop Vulnerability Scanner")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    app_path = os.path.join(script_dir, "ui", "app.py")
    
    # Check if app.py exists
    if not os.path.exists(app_path):
        print(f"❌ Could not find app.py at {app_path}")
        sys.exit(1)
    
    print("\n🚀 Starting Streamlit application...")
    print("📍 The UI will open in your browser at http://localhost:8501")
    print("🛑 Press Ctrl+C to stop the server\n")
    
    try:
        # Run streamlit
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", 
            app_path,
            "--server.port=8501",
            "--server.address=localhost"
        ], cwd=script_dir)
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
