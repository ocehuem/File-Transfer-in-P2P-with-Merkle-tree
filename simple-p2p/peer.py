import os
import socket
import json
import threading
import time
from utils import generate_peer_id, get_file_hash
from protocol import Message, MessageType
from config import DEFAULT_PORT, DISCOVERY_PORT, BUFFER_SIZE

class Peer:
    def __init__(self, shared_directory, port=DEFAULT_PORT):
        self.id = generate_peer_id()
        self.port = port
        self.shared_directory = shared_directory
        self.peers = {}  # {peer_id: (ip, port)}
        self.available_files = {}  # {file_hash: file_path}
        self.active_transfers = {}  # {transfer_id: status}
        
        # Create shared directory if it doesn't exist
        if not os.path.exists(shared_directory):
            os.makedirs(shared_directory)
            
        # Index available files
        self._index_files()
        
        # Start server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(5)
        
        # Start threads
        self.running = True
        self.server_thread = threading.Thread(target=self._server_loop)
        self.discovery_thread = threading.Thread(target=self._discovery_loop)
        self.server_thread.daemon = True
        self.discovery_thread.daemon = True
        
    def start(self):
        """Start the peer services"""
        print(f"Peer {self.id} starting on port {self.port}")
        print(f"Sharing files from {self.shared_directory}")
        self.server_thread.start()
        self.discovery_thread.start()
        
    def stop(self):
        """Stop the peer services"""
        self.running = False
        self.server_socket.close()
        
    def _index_files(self):
        """Index all files in the shared directory"""
        self.available_files = {}
        for filename in os.listdir(self.shared_directory):
            filepath = os.path.join(self.shared_directory, filename)
            if os.path.isfile(filepath):
                file_hash = get_file_hash(filepath)
                self.available_files[file_hash] = filepath
                print(f"Indexed file: {filename} ({file_hash})")
                
    def _server_loop(self):
        """Listen for incoming connections"""
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                handler = threading.Thread(target=self._handle_client, args=(client_sock, client_addr))
                handler.daemon = True
                handler.start()
            except Exception as e:
                if self.running:  # Only print if not caused by stopping
                    print(f"Server error: {e}")
                    
    def _handle_client(self, client_sock, client_addr):
        """Handle an incoming client connection"""
        try:
            # Receive message
            data = client_sock.recv(BUFFER_SIZE)
            if not data:
                return
                
            # Parse message
            message = Message.from_json(data.decode('utf-8'))
            
            # Handle message
            if message.type == MessageType.FILE_REQUEST:
                self._handle_file_request(client_sock, message)
            elif message.type == MessageType.FILE_QUERY:
                self._handle_file_query(client_sock, message)
                
        except Exception as e:
            print(f"Error handling client {client_addr}: {e}")
        finally:
            client_sock.close()
            
    def _handle_file_request(self, client_sock, message):
        """Handle a file request from another peer"""
        file_hash = message.content.get('file_hash')
        
        if file_hash in self.available_files:
            filepath = self.available_files[file_hash]
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            
            # Send file info
            response = Message(
                type=MessageType.FILE_RESPONSE,
                sender=self.id,
                content={
                    'file_hash': file_hash,
                    'filename': filename,
                    'filesize': filesize,
                    'status': 'available'
                }
            )
            client_sock.sendall(response.to_json().encode('utf-8'))
            
            # Send the file data
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(BUFFER_SIZE)
                    if not data:
                        break
                    client_sock.sendall(data)
                    
            print(f"Sent file {filename} to {message.sender}")
        else:
            # File not available
            response = Message(
                type=MessageType.FILE_RESPONSE,
                sender=self.id,
                content={
                    'file_hash': file_hash,
                    'status': 'unavailable'
                }
            )
            client_sock.sendall(response.to_json().encode('utf-8'))
    
    def _handle_file_query(self, client_sock, message):
        """Handle a file query from another peer"""
        query = message.content.get('query', '')
        results = []
        
        for file_hash, filepath in self.available_files.items():
            filename = os.path.basename(filepath)
            if query.lower() in filename.lower():
                results.append({
                    'file_hash': file_hash,
                    'filename': filename,
                    'filesize': os.path.getsize(filepath)
                })
                
        response = Message(
            type=MessageType.QUERY_RESPONSE,
            sender=self.id,
            content={
                'results': results
            }
        )
        client_sock.sendall(response.to_json().encode('utf-8'))
    
    def _discovery_loop(self):
        """Broadcast peer presence and listen for other peers"""
        discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        discovery_socket.bind(('0.0.0.0', DISCOVERY_PORT))
        
        # Start listening for broadcasts
        listen_thread = threading.Thread(target=self._listen_for_peers, args=(discovery_socket,))
        listen_thread.daemon = True
        listen_thread.start()
        
        # Periodically broadcast presence
        while self.running:
            try:
                # Broadcast presence
                announce_msg = Message(
                    type=MessageType.PEER_ANNOUNCE,
                    sender=self.id,
                    content={
                        'port': self.port,
                        'file_count': len(self.available_files)
                    }
                )
                discovery_socket.sendto(
                    announce_msg.to_json().encode('utf-8'), 
                    ('<broadcast>', DISCOVERY_PORT)
                )
                time.sleep(60)  # Announce every minute
            except Exception as e:
                print(f"Discovery broadcast error: {e}")
                time.sleep(5)
                
    def _listen_for_peers(self, discovery_socket):
        """Listen for peer announcements"""
        while self.running:
            try:
                data, addr = discovery_socket.recvfrom(BUFFER_SIZE)
                message = Message.from_json(data.decode('utf-8'))
                
                if message.type == MessageType.PEER_ANNOUNCE and message.sender != self.id:
                    # Add peer to known peers
                    peer_id = message.sender
                    peer_port = message.content.get('port', DEFAULT_PORT)
                    self.peers[peer_id] = (addr[0], peer_port)
                    print(f"Discovered peer: {peer_id} at {addr[0]}:{peer_port}")
            except Exception as e:
                print(f"Discovery listening error: {e}")
                
    def search_files(self, query):
        """Search for files matching the query across all peers"""
        results = []
        
        # First search locally
        for file_hash, filepath in self.available_files.items():
            filename = os.path.basename(filepath)
            if query.lower() in filename.lower():
                results.append({
                    'file_hash': file_hash,
                    'filename': filename,
                    'filesize': os.path.getsize(filepath),
                    'peer_id': self.id,
                    'location': 'local'
                })
                
        # Then query other peers
        for peer_id, (ip, port) in self.peers.items():
            try:
                # Connect to peer
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((ip, port))
                
                # Send query
                query_msg = Message(
                    type=MessageType.FILE_QUERY,
                    sender=self.id,
                    content={
                        'query': query
                    }
                )
                sock.sendall(query_msg.to_json().encode('utf-8'))
                
                # Receive response
                data = sock.recv(BUFFER_SIZE)
                response = Message.from_json(data.decode('utf-8'))
                
                if response.type == MessageType.QUERY_RESPONSE:
                    for file_info in response.content.get('results', []):
                        file_info['peer_id'] = peer_id
                        file_info['location'] = 'remote'
                        results.append(file_info)
                        
                sock.close()
            except Exception as e:
                print(f"Error querying peer {peer_id}: {e}")
                
        return results
        
    def download_file(self, file_hash, peer_id, destination=None):
        """Download a file from a specific peer"""
        if destination is None:
            destination = self.shared_directory
            
        if peer_id == self.id:
            print("File is available locally")
            return True
            
        if peer_id not in self.peers:
            print(f"Unknown peer: {peer_id}")
            return False
            
        ip, port = self.peers[peer_id]
        
        try:
            # Connect to peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            
            # Send file request
            request = Message(
                type=MessageType.FILE_REQUEST,
                sender=self.id,
                content={
                    'file_hash': file_hash
                }
            )
            sock.sendall(request.to_json().encode('utf-8'))
            
            # Get initial response
            data = sock.recv(BUFFER_SIZE)
            response = Message.from_json(data.decode('utf-8'))
            
            if response.type != MessageType.FILE_RESPONSE or response.content.get('status') != 'available':
                print("File not available from peer")
                sock.close()
                return False
                
            # Get file details
            filename = response.content.get('filename')
            filesize = response.content.get('filesize')
            
            print(f"Downloading {filename} ({filesize} bytes) from {peer_id}")
            
            # Create the destination file
            filepath = os.path.join(destination, filename)
            received = 0
            
            with open(filepath, 'wb') as f:
                while received < filesize:
                    data = sock.recv(BUFFER_SIZE)
                    if not data:
                        break
                        
                    f.write(data)
                    received += len(data)
                    
                    # Print progress
                    progress = (received / filesize) * 100
                    print(f"Progress: {progress:.1f}% ({received}/{filesize})", end='\r')
                    
            print(f"\nDownloaded {filename} to {filepath}")
            
            # Update file index
            self._index_files()
            
            return True
            
        except Exception as e:
            print(f"Download error: {e}")
            return False
