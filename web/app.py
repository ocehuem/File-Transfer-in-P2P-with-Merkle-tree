import os
import sys
import threading
import time
import subprocess
from flask import Flask, request, jsonify, send_from_directory

# Add parent directory to path for imports
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(parent_dir)

app = Flask(__name__, static_folder='.', template_folder='.')


PEERS_FILE_PATH = 'peer_output.txt'
# Global variables
peer_process = None
process_lock = threading.Lock()

# Default values
default_port = 8000
default_directory = os.path.abspath(os.path.join(parent_dir, 'shared'))

# Ensure default directory exists
if not os.path.exists(default_directory):
    os.makedirs(default_directory)

# Serve the main HTML page
@app.route('/')
def index():
    return send_from_directory('.', 'app.html')

# Serve the JS file
@app.route('/app.js')
def serve_js():
    return send_from_directory('.', 'app.js')

# API to start peer
@app.route('/api/start', methods=['POST'])
def start_peer():
    """Start the peer using client.py."""
    global peer_process
    
    with process_lock:
        if peer_process is not None and peer_process.poll() is None:
            return jsonify({'success': False, 'error': 'Peer is already running'})

        try:
            data = request.json or {}
            port = data.get('port', default_port)
            directory = data.get('directory', default_directory)

            if not os.path.exists(directory):
                os.makedirs(directory)

            client_path = os.path.join(parent_dir, 'p2p', 'client.py')
            cmd = [sys.executable, client_path, '--port', str(port), '--directory', directory]

            # Detect OS and open in new terminal
            if os.name == 'nt':  # Windows
                peer_process = subprocess.Popen(
                    ['start', 'cmd', '/k'] + cmd,
                    shell=True
                )
            elif sys.platform == 'darwin':  # macOS
                peer_process = subprocess.Popen(
                    ['open', '-a', 'Terminal.app'] + cmd
                )
            else:  # Linux/Unix
                peer_process = subprocess.Popen(
                    ['gnome-terminal', '--'] + cmd
                )
            output, errors = peer_process.communicate(input="3")
            print(output,"in",port)
            return jsonify({'success': True, 'message': 'Peer started successfully'})

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})






if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
