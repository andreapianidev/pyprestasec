import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# API Configuration
NVD_API_KEY = os.getenv('NVD_API_KEY', '')
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))

# UI Configuration
APP_TITLE = "PyPrestaSec - PrestaShop Vulnerability Scanner"
APP_ICON = "🛡️"

# Severity Colors
SEVERITY_COLORS = {
    'CRITICAL': '#FF0000',
    'HIGH': '#FF6600',
    'MEDIUM': '#FFCC00',
    'LOW': '#00CC00',
    'UNKNOWN': '#999999'
}

# Severity Icons
SEVERITY_ICONS = {
    'CRITICAL': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '🟢',
    'UNKNOWN': '⚪'
}

# Default scanning options
DEFAULT_MAX_CVE_RESULTS = 100
DEFAULT_RESULTS_PER_PAGE = 20
