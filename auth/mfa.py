import hmac
import base64
import struct
import hashlib
import time
import os

def generate_totp_secret():
    return base64.b32encode(os.urandom(10)).decode('utf-8')

def verify_totp(secret, token):
    # Allow a window of 1 step before or after to account for clock skew
    try:
        secret_bytes = base64.b32decode(secret, casefold=True)
        for i in range(-1, 2):
            t = int(time.time() / 30) + i
            time_bytes = struct.pack(">q", t)
            mac = hmac.new(secret_bytes, time_bytes, hashlib.sha1).digest()
            offset = mac[-1] & 0x0f
            binary = struct.unpack(">I", mac[offset:offset+4])[0] & 0x7fffffff
            expected_token = str(binary % 1000000).zfill(6)
            if hmac.compare_digest(expected_token, token):
                return True
        return False
    except Exception:
        return False

def get_totp_uri(secret, app_name, username):
    return f"otpauth://totp/{app_name}:{username}?secret={secret}&issuer={app_name}"
