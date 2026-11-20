"""Serve the frozen results and the newly checked benign sample, with no upload routes."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import subprocess
import sys

base = Path(__file__).resolve().parent
run = subprocess.run([sys.executable, str(base/'check_extract.py')], check=True, capture_output=True, text=True)
print(run.stdout, end='', flush=True)
health = json.dumps({
    'status':'ok', 'read_only':True, 'sample':'included benign PCAP',
    'feature_count':32, 'normal_ip_minute_count':60,
    'ai_score':'recomputed using fixed OCSVM',
    'combined_ids_input':'archived IDS flags; optional IDS engine output inspected separately',
    'verification_log':run.stdout.strip().splitlines(),
}).encode()

class View(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?',1)[0]
        if path == '/health':
            body, mime = health, 'application/json; charset=utf-8'
        elif path in ('/', '/dashboard.html'):
            body, mime = (base/'dashboard.html').read_bytes(), 'text/html; charset=utf-8'
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type',mime)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        self.send_error(405,'Read-only demo')

if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0',8080),View).serve_forever()
