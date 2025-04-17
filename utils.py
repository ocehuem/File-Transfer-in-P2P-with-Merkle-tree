import os
import hashlib
import uuid
import socket

def generate_peer_id():
    """Generate a unique peer ID"""
    return str(uuid.uuid4())

def get_file_hash(filepath):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read the file in chunks to avoid loading large files into memory
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_local_ip():
    """Get the local IP address"""
    try:
        # Create a socket to determine the IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # This doesn't actually connect
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        # Fallback
        return socket.gethostbyname(socket.gethostname())