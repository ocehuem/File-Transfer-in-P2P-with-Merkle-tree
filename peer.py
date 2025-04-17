import os
import socket
import json
import threading
import time
from utils import generate_peer_id, get_file_hash, get_local_ip
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
        self.server_thread.daemon = True
        
    def start(self):
        """Start the peer services"""
        print(f"Peer {self.id} starting on port {self.port}")
        print(f"Sharing files from {self.shared_directory}")
        self.server_thread.start()
        
        # Start discovery service
        self.discovery_service = PeerDiscovery(self.id, self.port, self.peers)
        self.discovery_service.start()
        
    def stop(self):
        """Stop the peer services"""
        self.running = False
        if hasattr(self, 'discovery_service'):
            self.discovery_service.stop()
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
        self.server_socket.settimeout(1.0)  # Add timeout to allow clean shutdown
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                handler = threading.Thread(target=self._handle_client, args=(client_sock, client_addr))
                handler.daemon = True
                handler.start()
            except socket.timeout:
                continue  # Just retry on timeout
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
            elif message.type == MessageType.GET_ALL_FILES:
                self._handle_get_all_files(client_sock, message)
                
        except Exception as e:
            print(f"Error handling client {client_addr}: {e}")
        finally:
            client_sock.close()
    
    def _handle_get_all_files(self, client_sock, message):
        """Handle a request for all files from another peer"""
        results = []
        for file_hash, filepath in self.available_files.items():
            filename = os.path.basename(filepath)
            results.append({
                'file_hash': file_hash,
                'filename': filename,
                'filesize': os.path.getsize(filepath)
            })
                
        response = Message(
            type=MessageType.ALL_FILES_RESPONSE,
            sender=self.id,
            content={
                'results': results
            }
        )
        client_sock.sendall(response.to_json().encode('utf-8'))
            
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
            
            # Wait for client to acknowledge and request data
            try:
                data = client_sock.recv(BUFFER_SIZE)
                if not data:
                    return
                    
                ack_message = Message.from_json(data.decode('utf-8'))
                if ack_message.type != MessageType.FILE_DATA_REQUEST:
                    return
                
                # Send the file data
                with open(filepath, 'rb') as f:
                    bytes_sent = 0
                    while bytes_sent < filesize:
                        chunk = f.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        client_sock.sendall(chunk)
                        bytes_sent += len(chunk)
                        
                print(f"Sent file {filename} to {message.sender}")
            except Exception as e:
                print(f"Error during file transfer: {e}")
                
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
        for peer_id, (ip, port) in list(self.peers.items()):
            try:
                # Connect to peer
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)  # Add timeout to prevent hanging
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
                # Remove unreachable peer
                self.peers.pop(peer_id, None)
                
        return results
    
    def get_all_peer_files(self):
        """Get all files from all peers"""
        all_files = {}  # {peer_id: [file_info]}
        
        # Add local files
        local_files = []
        for file_hash, filepath in self.available_files.items():
            filename = os.path.basename(filepath)
            local_files.append({
                'file_hash': file_hash,
                'filename': filename,
                'filesize': os.path.getsize(filepath),
                'location': 'local'
            })
        all_files[self.id] = local_files
        
        # Query all known peers
        for peer_id, (ip, port) in list(self.peers.items()):
            try:
                # Connect to peer
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                
                # Send request for all files
                query_msg = Message(
                    type=MessageType.GET_ALL_FILES,
                    sender=self.id,
                    content={}
                )
                sock.sendall(query_msg.to_json().encode('utf-8'))
                
                # Receive response
                data = sock.recv(BUFFER_SIZE)
                response = Message.from_json(data.decode('utf-8'))
                
                if response.type == MessageType.ALL_FILES_RESPONSE:
                    peer_files = []
                    for file_info in response.content.get('results', []):
                        file_info['location'] = 'remote'
                        peer_files.append(file_info)
                    all_files[peer_id] = peer_files
                    
                sock.close()
            except Exception as e:
                print(f"Error getting files from peer {peer_id}: {e}")
                # Remove unreachable peer
                self.peers.pop(peer_id, None)
                
        return all_files
        
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
            sock.settimeout(10)  # Add timeout for connection
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
            filesize = int(response.content.get('filesize'))
            
            print(f"Downloading {filename} ({filesize} bytes) from {peer_id}")
            
            # Create the destination file
            filepath = os.path.join(destination, filename)
            
            # Send acknowledgment and request file data
            data_request = Message(
                type=MessageType.FILE_DATA_REQUEST,
                sender=self.id,
                content={
                    'file_hash': file_hash
                }
            )
            sock.sendall(data_request.to_json().encode('utf-8'))
            
            # Set longer timeout for file transfer
            sock.settimeout(30)
            
            # Receive file data
            received = 0
            with open(filepath, 'wb') as f:
                while received < filesize:
                    try:
                        chunk = sock.recv(BUFFER_SIZE)
                        if not chunk:
                            break
                            
                        f.write(chunk)
                        received += len(chunk)
                        
                        # Print progress
                        progress = (received / filesize) * 100
                        print(f"Progress: {progress:.1f}% ({received}/{filesize})", end='\r')
                    except socket.timeout:
                        print("\nTimeout during file transfer, retrying...")
                        continue
                    
            print(f"\nDownloaded {filename} to {filepath}")
            
            # Verify file integrity
            if received < filesize:
                print(f"Warning: Incomplete download ({received}/{filesize} bytes)")
                return False
                
            # Update file index
            self._index_files()
            
            return True
            
        except Exception as e:
            print(f"Download error: {e}")
            return False


class PeerDiscovery:
    """Handles peer discovery using UDP broadcasts"""
    
    def __init__(self, peer_id, port, peer_list):
        self.peer_id = peer_id
        self.port = port
        self.peer_list = peer_list  # Reference to parent's peer list
        self.running = False
        self.local_ip = get_local_ip()
        
        # Create UDP socket for discovery
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Set socket to non-blocking mode
        self.socket.setblocking(0)
        
        # Set larger buffer size and bind to any available port in discovery range
        try:
            self.socket.bind(('0.0.0.0', DISCOVERY_PORT))
        except OSError:
            # If port is in use, try a different one
            self.socket.bind(('0.0.0.0', 0))
            print(f"Using alternate discovery port: {self.socket.getsockname()[1]}")
        
    def start(self):
        """Start the discovery service"""
        self.running = True
        print(f"Starting peer discovery service (ID: {self.peer_id})")
        
        # Start listener thread
        self.listener_thread = threading.Thread(target=self._listen_loop)
        self.listener_thread.daemon = True
        self.listener_thread.start()
        
        # Start broadcast thread
        self.broadcast_thread = threading.Thread(target=self._broadcast_loop)
        self.broadcast_thread.daemon = True
        self.broadcast_thread.start()
        
        # Immediately announce presence
        self._broadcast_presence()
        
    def stop(self):
        """Stop the discovery service"""
        self.running = False
        try:
            self.socket.close()
        except:
            pass
        
    def _listen_loop(self):
        """Listen for peer announcements"""
        while self.running:
            try:
                try:
                    data, addr = self.socket.recvfrom(BUFFER_SIZE)
                except BlockingIOError:
                    # No data available
                    time.sleep(0.1)
                    continue
                    
                try:
                    message = Message.from_json(data.decode('utf-8'))
                    
                    if message.type == MessageType.PEER_ANNOUNCE and message.sender != self.peer_id:
                        # Add peer to known peers
                        peer_id = message.sender
                        peer_port = message.content.get('port', DEFAULT_PORT)
                        
                        # Store the actual IP we received from, not what they might claim
                        if addr[0] not in ('0.0.0.0', '127.0.0.1'):
                            self.peer_list[peer_id] = (addr[0], peer_port)
                            print(f"Discovered peer: {peer_id} at {addr[0]}:{peer_port}")
                            
                            # Send an immediate announcement back to help with bi-directional discovery
                            self._send_direct_announce(addr[0], DISCOVERY_PORT)
                except json.JSONDecodeError:
                    # Ignore invalid packets
                    pass
            except Exception as e:
                if self.running:  # Only print if not caused by stopping
                    print(f"Discovery listening error: {e}")
                    time.sleep(1)  # Prevent tight loop on repeated errors
                
    def _broadcast_loop(self):
        """Periodically broadcast presence"""
        while self.running:
            try:
                self._broadcast_presence()
                # Send to specific peers directly to ensure connectivity
                for peer_id, (ip, port) in list(self.peer_list.items()):
                    try:
                        self._send_direct_announce(ip, DISCOVERY_PORT)
                    except:
                        pass
                time.sleep(15)  # Announce every 15 seconds
            except Exception as e:
                if self.running:  # Only print if not caused by stopping
                    print(f"Discovery broadcast error: {e}")
                time.sleep(5)  # Wait before retrying
    
    def _broadcast_presence(self):
        """Broadcast peer presence to the network"""
        try:
            # Create the announcement message
            announce_msg = Message(
                type=MessageType.PEER_ANNOUNCE,
                sender=self.peer_id,
                content={
                    'port': self.port,
                    'timestamp': time.time(),
                    'file_count': len(self.peer_list)
                }
            )
            
            # Send to broadcast address
            encoded_msg = announce_msg.to_json().encode('utf-8')
            
            # Try different broadcast addresses
            broadcast_addresses = [
                '<broadcast>',  # Generic broadcast
                '255.255.255.255',  # Global broadcast
                '.'.join(self.local_ip.split('.')[:3] + ['255'])  # Subnet broadcast
            ]
            
            for addr in broadcast_addresses:
                try:
                    self.socket.sendto(encoded_msg, (addr, DISCOVERY_PORT))
                except:
                    pass
        except Exception as e:
            print(f"Error broadcasting presence: {e}")
    
    def _send_direct_announce(self, target_ip, target_port):
        """Send a direct announcement to a specific IP"""
        try:
            announce_msg = Message(
                type=MessageType.PEER_ANNOUNCE,
                sender=self.peer_id,
                content={
                    'port': self.port,
                    'timestamp': time.time(),
                    'direct': True
                }
            )
            
            encoded_msg = announce_msg.to_json().encode('utf-8')
            self.socket.sendto(encoded_msg, (target_ip, target_port))
        except Exception as e:
            print(f"Error sending direct announcement: {e}")