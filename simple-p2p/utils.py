import os
import uuid
import hashlib
import socket

def generate_peer_id():
    """Generate a unique peer ID"""
    # Use MAC address as part of ID to make it more unique
    mac = uuid.getnode()
    # Add a random component
    rand = uuid.uuid4().hex[:6]
    return f"{mac}-{rand}"

def get_file_hash(filepath):
    """Calculate SHA-256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        # Read file in chunks to handle large files
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def get_local_ip():
    """Get the local IP address"""
    try:
        # This creates a socket that doesn't actually connect
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # This trick causes the socket to get a local IP
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'
