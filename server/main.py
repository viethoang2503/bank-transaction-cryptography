"""Entry point for uvicorn: `uvicorn server.main:app`. Mode comes from TBA_MODE."""
from .app import create_app

app = create_app()
