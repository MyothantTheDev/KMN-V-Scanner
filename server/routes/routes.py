from flask import Blueprint
from server.services.scanner_services import index, search_vulns, scan_port

blureprint = Blueprint('routes', __name__)


base_url = '/'
search_vulns = '/search_vulns'
scan_port = '/scan_port'

blureprint.add_url_rule(base_url, view_func=index)
blureprint.add_url_rule(search_vulns, view_func=search_vulns)
blureprint.add_url_rule(scan_port, view_func=scan_port)