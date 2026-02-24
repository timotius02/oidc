"""
Template configuration for the application.
Separate module to avoid circular imports.
"""
from pathlib import Path
from fastapi.templating import Jinja2Templates

# Configure Jinja2 templates
TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
