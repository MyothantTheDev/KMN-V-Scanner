from flask import render_template, request
from server.config.version import __version__, __description__

def index():
  """Render the index page."""
  return render_template('index.html', version=__version__, description=__description__)


def search_vulns():...

def scan_port():...