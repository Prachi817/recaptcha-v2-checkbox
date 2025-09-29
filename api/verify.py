# api/verify.py
import os, json
from http.server import BaseHTTPRequestHandler
import requests

SECRET = os.environ.get("RECAPTCHA_SECRET_KEY", "6LdOHpArAAAAAFghvE60W9_o4pUhG2ZM_kJgWfYR")

def respond(h, status, payload):
    body = json.dumps(payload).encode()
    h.send_response(status)
    h.send_header("Content-Type", "application/json")
    h.send_header("Access-Control-Allow-Origin", "*")
    h.send_header("Access-Control-Allow-Headers", "Content-Type")
    h.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
    h.end_headers()
    h.wfile.write(body)

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        respond(self, 204, {})

    def do_POST(self):
        try:
            n = int(self.headers.get("content-length", 0))
            raw = self.rfile.read(n) if n else b""
            ctype = (self.headers.get("content-type") or "").lower()
            token = None
            if "application/json" in ctype:
                token = (json.loads(raw.decode() or "{}") or {}).get("token")
            else:
                # handle HTML form posts: g-recaptcha-response
                from urllib.parse import parse_qs
                token = (parse_qs(raw.decode()).get("g-recaptcha-response") or [None])[0]
        except Exception:
            return respond(self, 400, {"success": False, "error": "bad request"})

        if not SECRET:
            return respond(self, 500, {"success": False, "error": "missing RECAPTCHA_SECRET_KEY"})
        if not token:
            return respond(self, 400, {"success": False, "error": "missing token"})

        r = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": SECRET, "response": token},
            timeout=10
        )
        data = r.json()
        return respond(self, 200 if data.get("success") else 400, data)
