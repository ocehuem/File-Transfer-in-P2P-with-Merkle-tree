import os
import socket
import json
import threading
import time
import csv
import datetime
from hashlib import sha256
from cryptography.fernet import Fernet

# Constants
DEFAULT_PORT = 8000
DISCOVERY_PORT = 8001
BUFFER_SIZE = 65536  # Increased for larger file transfers

# Encryption key
KEY = 'epVKiOHn7J0sZcJ4-buWQ5ednv3csHdQHfvEKk0qVvk='

# Message types
class MessageType:
    FILE_REQUEST = "file_request"
    FILE_RESPONSE = "file_response"
    FILE_QUERY = "file_query"
    FILE_DATA_REQUEST = "file_data_request"
    ALL_FILES_RESPONSE = "all_files_response"
    GET_ALL_FILES = "get_all_files"
    FILE_UPLOAD = "file_upload"
    FILE_UPLOAD_ACK = "file_upload_ack"
    FILE_UPLOAD_RESULT = "file_upload_result"

# Message class for peer communication
class Message:
    def __init__(self, type, sender, content=None):
        self.type = type
        self.sender = sender
        self.content = content or {}
        self.timestamp = time.time()
    # ... rest of the file remains the same ...
        
    def to_json(self):
        return json.dumps({
            'type': self.type,
            'sender': self.sender,
            'content': self.content,
            'timestamp': self.timestamp
        })
    
    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        msg = cls(data['type'], data['sender'], data['content'])
        msg.timestamp = data.get('timestamp', time.time())
        return msg

# Utility functions
def generate_peer_id():
    hostname = socket.gethostname()
    return sha256(f"{hostname}:{time.time()}".encode()).hexdigest()[:12]

def get_file_hash(filepath):
    hasher = sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'

# Function to encrypt data using Fernet symmetric encryption
def encrypt_data(data):
    fernet = Fernet(KEY)
    if isinstance(data, str):
        return fernet.encrypt(data.encode())
    return fernet.encrypt(data)

# Function to decrypt data using Fernet symmetric encryption
def decrypt_data(data):
    fernet = Fernet(KEY)
    decrypted = fernet.decrypt(data)
    try:
        return decrypted.decode()
    except UnicodeDecodeError:
        # If it's binary data, return as is
        return decrypted

# Function to break a file into chunks for building the merkle tree
def chunk_file(file_path, chunk_size=1024):
    chunks = []
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if chunk:
                    # Convert binary to string for consistent merkle tree calculation
                    chunks.append(chunk.decode('utf-8', errors='ignore'))
                else:
                    break
    except Exception as e:
        print(f"Error chunking file: {e}")
        return [""]  # Return a single empty chunk on error
    
    return chunks if chunks else [""]  # Ensure at least one chunk even for empty files

# Function to create a Merkle tree from file chunks and 
# returns the root hash value of the tree
def merkle_tree(chunks):
    if len(chunks) == 1:
        return sha256(chunks[0].encode()).hexdigest()

    mid = len(chunks) // 2
    left_hash = merkle_tree(chunks[:mid])
    right_hash = merkle_tree(chunks[mid:])
    
    # Debug option - commented out for production
    # print(f"Left Hash: {left_hash}\nRight Hash: {right_hash}\n")

    return sha256((left_hash + right_hash).encode()).hexdigest()

def log_to_csv(log_data):
    with open("logs.csv", mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(log_data)

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
            
        # Create logs directory if it doesn't exist
        if not os.path.exists("logs"):
            os.makedirs("logs")
            
        # Create logs.csv if it doesn't exist
        if not os.path.exists("logs.csv"):
            with open("logs.csv", mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Date", "Timestamp", "Client Address", "Event", "Filename", "Status"])
                
        # Index available files
        self._index_files()
        
        # Start server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
        except OSError as e:
            print(f"Error binding to port {self.port}: {e}")
            # Try another port
            self.port = 0  # Let OS choose a free port
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.port = self.server_socket.getsockname()[1]  # Get the assigned port
            print(f"Using alternative port: {self.port}")
        
        # Start threads
        self.running = True
        self.server_thread = threading.Thread(target=self._server_loop)
        self.server_thread.daemon = True

        def discover_peers(self):
            """Basic peer discovery using broadcast"""
            discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            discovery_socket.settimeout(2)
            
            message = json.dumps({
                'type': 'discovery',
                'peer_id': self.id,
                'ip': get_local_ip(),
                'port': self.port
            })
            
            try:
                # Send broadcast
                discovery_socket.sendto(message.encode(), ('255.255.255.255', DISCOVERY_PORT))
                
                # Listen for responses
                while True:
                    try:
                        data, addr = discovery_socket.recvfrom(1024)
                        peer_info = json.loads(data.decode())
                        if peer_info['peer_id'] != self.id:  # Don't add self
                            self.peers[peer_info['peer_id']] = (peer_info['ip'], peer_info['port'])
                            print(f"Discovered peer: {peer_info['peer_id']} at {peer_info['ip']}:{peer_info['port']}")
                    except socket.timeout:
                        break
            finally:
                discovery_socket.close()
                
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
        try:
            self.server_socket.close()
        except:
            pass
        
    def _index_files(self):
        """Index all files in the shared directory"""
        self.available_files = {}
        if not os.path.exists(self.shared_directory):
            return
            
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
                self._handle_file_request(client_sock, message, client_addr)
            elif message.type == MessageType.FILE_QUERY:
                self._handle_file_query(client_sock, message)
            elif message.type == MessageType.GET_ALL_FILES:
                self._handle_get_all_files(client_sock, message)
            elif message.type == MessageType.FILE_UPLOAD:
                self._handle_file_upload(client_sock, message, client_addr)
                
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
        log_data = [str(datetime.datetime.now().date()), str(datetime.datetime.now().time()), 
                    str(client_sock.getpeername()), "Get File Names", "", "Success"]
        log_to_csv(log_data)
        
    def _handle_file_upload(self, client_sock, message, client_addr):
        """Handle a file upload from another peer with Merkle tree verification"""
        filename = message.content.get('filename')
        
        # Send acknowledgment for filename
        response = Message(
            type=MessageType.FILE_UPLOAD_ACK,
            sender=self.id,
            content={'status': 'filename received'}
        )
        client_sock.sendall(response.to_json().encode('utf-8'))
        
        # Receive encrypted file data in chunks
        file_data = b''
        while True:
            chunk = client_sock.recv(BUFFER_SIZE)
            if not chunk or b'END_OF_FILE_MARKER' in chunk:
                if b'END_OF_FILE_MARKER' in chunk:
                    # Remove the marker from the last chunk
                    marker_index = chunk.find(b'END_OF_FILE_MARKER')
                    file_data += chunk[:marker_index]
                break
            file_data += chunk
        
        # Decrypt and save file
        filepath = os.path.join(self.shared_directory, filename)
        try:
            decrypted_data = decrypt_data(file_data)
            
            # Determine if the file is binary
            try:
                decrypted_str = decrypted_data if isinstance(decrypted_data, str) else decrypted_data.decode()
                with open(filepath, 'w') as f:
                    f.write(decrypted_str)
            except (UnicodeDecodeError, AttributeError):
                # If decoding fails, treat as binary data
                with open(filepath, 'wb') as f:
                    f.write(decrypted_data if isinstance(decrypted_data, bytes) else decrypted_data.encode())
                
            # Receive the Merkle tree root hash
            hash_data = client_sock.recv(BUFFER_SIZE)
            client_hash = hash_data.decode()
            
            # Calculate our own Merkle tree hash for verification
            chunks = chunk_file(filepath)
            server_hash = merkle_tree(chunks)
            
            # Compare hashes
            if server_hash == client_hash:
                response = Message(
                    type=MessageType.FILE_UPLOAD_RESULT,
                    sender=self.id,
                    content={'status': 'success'}
                )
                client_sock.sendall(response.to_json().encode('utf-8'))
                log_data = [str(datetime.datetime.now().date()), str(datetime.datetime.now().time()), 
                           str(client_addr), "Upload", filename, "Successful"]
                log_to_csv(log_data)
                print(f"File {filename} uploaded successfully. Merkle tree verification passed.")
            else:
                response = Message(
                    type=MessageType.FILE_UPLOAD_RESULT,
                    sender=self.id,
                    content={'status': 'failure', 'reason': 'hash mismatch'}
                )
                client_sock.sendall(response.to_json().encode('utf-8'))
                log_data = [str(datetime.datetime.now().date()), str(datetime.datetime.now().time()), 
                           str(client_addr), "Upload", filename, "Unsuccessful"]
                log_to_csv(log_data)
                print(f"File {filename} upload failed. Merkle tree verification failed.")
                
            # Update file index after successful upload
            self._index_files()
        except Exception as e:
            response = Message(
                type=MessageType.FILE_UPLOAD_RESULT,
                sender=self.id,
                content={'status': 'failure', 'reason': str(e)}
            )
            client_sock.sendall(response.to_json().encode('utf-8'))
            log_data = [str(datetime.datetime.now().date()), str(datetime.datetime.now().time()), 
                       str(client_addr), "Upload", filename, f"Error: {str(e)}"]
            log_to_csv(log_data)
            print(f"Error during file upload: {e}")
            
    def _handle_file_request(self, client_sock, message, client_addr):
        """Handle a file request from another peer with Merkle tree verification"""
        file_hash = message.content.get('file_hash')
        
        if file_hash in self.available_files:
            filepath = self.available_files[file_hash]
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            
            # Calculate Merkle tree hash for the file
            chunks = chunk_file(filepath)
            merkle_hash = merkle_tree(chunks)
            
            # Send file info with merkle hash
            response = Message(
                type=MessageType.FILE_RESPONSE,
                sender=self.id,
                content={
                    'file_hash': file_hash,
                    'filename': filename,
                    'filesize': filesize,
                    'merkle_hash': merkle_hash,
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
                
                # Read file data
                try:
                    with open(filepath, 'rb') as f:
                        file_data = f.read()
                except Exception as e:
                    print(f"Error reading file: {e}")
                ##########
                # Read file data
                try:
                    with open(filepath, 'rb') as f:
                        file_data = f.read()
                        
                    # Encrypt file data for secure transmission
                    encrypted_data = encrypt_data(file_data)
                    
                    # Send the encrypted file data
                    client_sock.sendall(encrypted_data)
                    
                    # Log successful file transfer
                    log_data = [str(datetime.datetime.now().date()), str(datetime.datetime.now().time()), 
                               str(client_addr), "Download", filename, "Successful"]
                    log_to_csv(log_data)
                    print(f"File {filename} sent to {client_addr[0]}:{client_addr[1]}")
                    
                except Exception as e:
                    print(f"Error sending file: {e}")
                    log_data = [str(datetime.datetime.now().date()), str(datetime.datetime.now().time()), 
                               str(client_addr), "Download", filename, f"Error: {str(e)}"]
                    log_to_csv(log_data)
            
            else:
                # File data request was not received
                print(f"File data request not received from {client_addr}")
                
        else:
            # File not found
            response = Message(
                type=MessageType.FILE_RESPONSE,
                sender=self.id,
                content={
                    'status': 'not_available',
                    'message': 'File not found'
                }
            )
            client_sock.sendall(response.to_json().encode('utf-8'))
            log_data = [str(datetime.datetime.now().date()), str(datetime.datetime.now().time()), 
                       str(client_addr), "Download", file_hash, "File Not Found"]
            log_to_csv(log_data)
    
    def _handle_file_query(self, client_sock, message):
        """Handle a file query from another peer"""
        query = message.content.get('query', '').lower()
        results = []
        
        for file_hash, filepath in self.available_files.items():
            filename = os.path.basename(filepath)
            if query in filename.lower():
                results.append({
                    'file_hash': file_hash,
                    'filename': filename,
                    'filesize': os.path.getsize(filepath)
                })
                
        response = Message(
            type=MessageType.FILE_RESPONSE,
            sender=self.id,
            content={
                'results': results
            }
        )
        client_sock.sendall(response.to_json().encode('utf-8'))
    
    def search_files(self, query):
        """Search for files across all peers"""
        results = []
        
        # First search local files
        local_results = []
        for file_hash, filepath in self.available_files.items():
            filename = os.path.basename(filepath)
            if query.lower() in filename.lower():
                local_results.append({
                    'file_hash': file_hash,
                    'filename': filename,
                    'filesize': os.path.getsize(filepath),
                    'peer_id': self.id,
                    'location': 'local'
                })
        
        results.extend(local_results)
        
        # Then search remote peers
        for peer_id, (ip, port) in self.peers.items():
            if peer_id == self.id:
                continue
                
            try:
                # Connect to peer
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.settimeout(5)  # 5 second timeout
                peer_socket.connect((ip, port))
                
                # Send query
                message = Message(
                    type=MessageType.FILE_QUERY,
                    sender=self.id,
                    content={
                        'query': query
                    }
                )
                peer_socket.sendall(message.to_json().encode('utf-8'))
                
                # Receive response
                data = peer_socket.recv(BUFFER_SIZE)
                response = Message.from_json(data.decode('utf-8'))
                
                # Process results
                if response.type == MessageType.FILE_RESPONSE:
                    for file_info in response.content.get('results', []):
                        file_info['peer_id'] = peer_id
                        file_info['location'] = 'remote'
                        results.append(file_info)
                        
            except Exception as e:
                print(f"Error searching files on peer {peer_id}: {e}")
            finally:
                peer_socket.close()
                
        return results
    
    def get_all_files(self):
        """Get all files from all peers"""
        all_files = {
            'local': [],
            'remote': {}
        }
        
        # Get local files
        for file_hash, filepath in self.available_files.items():
            filename = os.path.basename(filepath)
            all_files['local'].append({
                'file_hash': file_hash,
                'filename': filename,
                'filesize': os.path.getsize(filepath)
            })
            
        # Get remote files
        for peer_id, (ip, port) in self.peers.items():
            if peer_id == self.id:
                continue
                
            try:
                # Connect to peer
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.settimeout(5)  # 5 second timeout
                peer_socket.connect((ip, port))
                
                # Send request
                message = Message(
                    type=MessageType.GET_ALL_FILES,
                    sender=self.id,
                    content={}
                )
                peer_socket.sendall(message.to_json().encode('utf-8'))
                
                # Receive response
                data = peer_socket.recv(BUFFER_SIZE)
                response = Message.from_json(data.decode('utf-8'))
                
                # Process results
                if response.type == MessageType.ALL_FILES_RESPONSE:
                    all_files['remote'][peer_id] = response.content.get('results', [])
                        
            except Exception as e:
                print(f"Error getting files from peer {peer_id}: {e}")
            finally:
                peer_socket.close()
                
        return all_files
        
    def download_file(self, file_hash, peer_id, destination_folder):
        """Download a file from a peer with Merkle tree verification"""
        if peer_id == self.id:
            # File is local
            if file_hash in self.available_files:
                filepath = self.available_files[file_hash]
                filename = os.path.basename(filepath)
                destination_path = os.path.join(destination_folder, filename)
                
                if os.path.exists(destination_path):
                    print(f"File already exists at {destination_path}")
                    return True
                    
                try:
                    # Copy file
                    import shutil
                    shutil.copy2(filepath, destination_path)
                    print(f"File copied to {destination_path}")
                    return True
                except Exception as e:
                    print(f"Error copying file: {e}")
                    return False
            else:
                print("File not found locally.")
                return False
        
        # Check if we know this peer
        if peer_id not in self.peers:
            print(f"Unknown peer: {peer_id}")
            return False
            
        peer_ip, peer_port = self.peers[peer_id]
        
        try:
            # Connect to peer
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.settimeout(30)  # Longer timeout for file transfers
            peer_socket.connect((peer_ip, peer_port))
            
            # Send file request
            message = Message(
                type=MessageType.FILE_REQUEST,
                sender=self.id,
                content={
                    'file_hash': file_hash
                }
            )
            peer_socket.sendall(message.to_json().encode('utf-8'))
            
            # Receive file info
            data = peer_socket.recv(BUFFER_SIZE)
            response = Message.from_json(data.decode('utf-8'))
            
            if response.type != MessageType.FILE_RESPONSE or response.content.get('status') != 'available':
                print("File not available.")
                return False
                
            filename = response.content.get('filename')
            filesize = response.content.get('filesize')
            merkle_hash = response.content.get('merkle_hash')
            
            print(f"Downloading {filename} ({filesize} bytes)...")
            
            # Send file data request
            data_request = Message(
                type=MessageType.FILE_DATA_REQUEST,
                sender=self.id,
                content={
                    'file_hash': file_hash
                }
            )
            peer_socket.sendall(data_request.to_json().encode('utf-8'))
            
            # Receive file data
            encrypted_data = b''
            received_bytes = 0
            
            while received_bytes < filesize * 1.5:  # Allow for encryption overhead
                chunk = peer_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                encrypted_data += chunk
                received_bytes += len(chunk)
                
            # Create destination folder if it doesn't exist
            if not os.path.exists(destination_folder):
                os.makedirs(destination_folder)
                
            # Decrypt and save file
            filepath = os.path.join(destination_folder, filename)
            try:
                decrypted_data = decrypt_data(encrypted_data)
                
                # Determine if the file is binary
                try:
                    decrypted_str = decrypted_data if isinstance(decrypted_data, str) else decrypted_data.decode()
                    with open(filepath, 'w') as f:
                        f.write(decrypted_str)
                except (UnicodeDecodeError, AttributeError):
                    # If decoding fails, treat as binary data
                    with open(filepath, 'wb') as f:
                        f.write(decrypted_data if isinstance(decrypted_data, bytes) else decrypted_data.encode())
                    
                # Verify file integrity using Merkle tree
                chunks = chunk_file(filepath)
                calculated_hash = merkle_tree(chunks)
                
                if calculated_hash == merkle_hash:
                    print("File integrity verified using Merkle tree!")
                    return True
                else:
                    print("File integrity check failed. The file may be corrupted.")
                    return False
                    
            except Exception as e:
                print(f"Error saving file: {e}")
                return False
                
        except Exception as e:
            print(f"Error downloading file: {e}")
            return False
        finally:
            peer_socket.close()
    
    def upload_file(self, filepath, peer_id):
        """Upload a file to another peer with Merkle tree verification"""
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return False
            
        if peer_id not in self.peers:
            print(f"Unknown peer: {peer_id}")
            return False
            
        peer_ip, peer_port = self.peers[peer_id]
        filename = os.path.basename(filepath)
        
        try:
            # Connect to peer
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.settimeout(30)  # Longer timeout for file uploads
            peer_socket.connect((peer_ip, peer_port))
            
            # Send upload request
            message = Message(
                type=MessageType.FILE_UPLOAD,
                sender=self.id,
                content={
                    'filename': filename
                }
            )
            peer_socket.sendall(message.to_json().encode('utf-8'))
            
            # Wait for acknowledgment
            data = peer_socket.recv(BUFFER_SIZE)
            ack = Message.from_json(data.decode('utf-8'))
            
            if ack.type != MessageType.FILE_UPLOAD_ACK:
                print("Upload not acknowledged.")
                return False
                
            # Read and encrypt file data
            with open(filepath, 'rb') as f:
                file_data = f.read()
                
            encrypted_data = encrypt_data(file_data)
            
            # Send encrypted data
            peer_socket.sendall(encrypted_data)
            # Send end marker
            peer_socket.sendall(b'END_OF_FILE_MARKER')
            
            # Calculate and send Merkle tree hash
            chunks = chunk_file(filepath)
            merkle_hash = merkle_tree(chunks)
            peer_socket.sendall(merkle_hash.encode())
            
            # Wait for upload result
            result_data = peer_socket.recv(BUFFER_SIZE)
            result = Message.from_json(result_data.decode('utf-8'))
            
            if result.type == MessageType.FILE_UPLOAD_RESULT and result.content.get('status') == 'success':
                print(f"File {filename} uploaded successfully!")
                return True
            else:
                reason = result.content.get('reason', 'Unknown error')
                print(f"Upload failed: {reason}")
                return False
                
        except Exception as e:
            print(f"Error uploading file: {e}")
            return False
        finally:
            peer_socket.close()

# PeerDiscovery class for peer discovery service
class PeerDiscovery:
    def __init__(self, peer_id, peer_port, peers_dict):
        self.peer_id = peer_id
        self.peer_port = peer_port
        self.peers = peers_dict  # Reference to the peer's peers dictionary
        self.running = False
        self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.listen_socket.bind(('0.0.0.0', DISCOVERY_PORT))
        except Exception as e:
            print(f"Error binding discovery socket: {e}")
            
    def start(self):
        """Start the discovery service"""
        self.running = True
        
        # Start listen thread
        self.listen_thread = threading.Thread(target=self._listen_loop)
        self.listen_thread.daemon = True
        self.listen_thread.start()
        
        # Start broadcast thread
        self.broadcast_thread = threading.Thread(target=self._broadcast_loop)
        self.broadcast_thread.daemon = True
        self.broadcast_thread.start()
        
    def stop(self):
        """Stop the discovery service"""
        self.running = False
        try:
            self.broadcast_socket.close()
            self.listen_socket.close()
        except:
            pass
            
    def _listen_loop(self):
        """Listen for discovery broadcasts"""
        self.listen_socket.settimeout(1.0)  # Add timeout to allow clean shutdown
        while self.running:
            try:
                data, addr = self.listen_socket.recvfrom(1024)
                message = json.loads(data.decode())
                
                if message.get('type') == 'discovery' and message.get('peer_id') != self.peer_id:
                    peer_id = message.get('peer_id')
                    peer_ip = message.get('ip')
                    peer_port = message.get('port')
                    
                    # Add to peers dictionary
                    self.peers[peer_id] = (peer_ip, peer_port)
                    print(f"Discovered peer: {peer_id} at {peer_ip}:{peer_port}")
                    
                    # Send response
                    response = json.dumps({
                        'type': 'discovery_response',
                        'peer_id': self.peer_id,
                        'ip': get_local_ip(),
                        'port': self.peer_port
                    })
                    self.broadcast_socket.sendto(response.encode(), addr)
                    
                elif message.get('type') == 'discovery_response' and message.get('peer_id') != self.peer_id:
                    peer_id = message.get('peer_id')
                    peer_ip = message.get('ip')
                    peer_port = message.get('port')
                    
                    # Add to peers dictionary
                    self.peers[peer_id] = (peer_ip, peer_port)
                    print(f"Received discovery response from peer: {peer_id} at {peer_ip}:{peer_port}")
                    
            except socket.timeout:
                continue  # Just retry on timeout
            except Exception as e:
                if self.running:  # Only print if not caused by stopping
                    print(f"Discovery listen error: {e}")
                    
    def _broadcast_loop(self):
        """Periodically broadcast discovery messages"""
        while self.running:
            try:
                message = json.dumps({
                    'type': 'discovery',
                    'peer_id': self.peer_id,
                    'ip': get_local_ip(),
                    'port': self.peer_port
                })
                self.broadcast_socket.sendto(message.encode(), ('255.255.255.255', DISCOVERY_PORT))
            except Exception as e:
                print(f"Discovery broadcast error: {e}")
                
            time.sleep(30)  # Broadcast every 30 seconds

# Main function
def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='P2P File Sharing with Merkle Tree Verification')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port to listen on')
    parser.add_argument('--dir', type=str, default='./shared', help='Directory to share files from')
    args = parser.parse_args()
    
    # Create and start peer
    peer = Peer(shared_directory=args.dir, port=args.port)
    peer.start()
    
    print("\nP2P File Sharing with Merkle Tree Verification")
    print("===================================================")
    print(f"Your peer ID: {peer.id}")
    print(f"Listening on port: {peer.port}")
    print(f"Sharing files from: {peer.shared_directory}")
    
    try:
        while True:
            print("\nOptions:")
            print("1. Search for files")
            print("2. List local files")
            print("3. List known peers")
            print("4. Download a file")
            print("5. Upload a file")
            print("6. View all peer files")
            print("7. Verify file integrity")
            print("8. Quit")
            
            choice = input("\nEnter your choice: ")
            
            if choice == '1':
                query = input("Enter search query: ")
                results = peer.search_files(query)
                
                if not results:
                    print("No files found matching your query.")
                else:
                    print("\nSearch Results:")
                    for i, result in enumerate(results):
                        location = "Local" if result['location'] == 'local' else f"Remote ({result['peer_id']})"
                        print(f"{i+1}. {result['filename']} - {result['filesize']} bytes - {location}")
                
            elif choice == '2':
                print("\nLocal Files:")
                for file_hash, filepath in peer.available_files.items():
                    filename = os.path.basename(filepath)
                    filesize = os.path.getsize(filepath)
                    print(f"{filename} - {filesize} bytes - {file_hash[:8]}...")
                
            elif choice == '3':
                print("\nKnown Peers:")
                if not peer.peers:
                    print("No peers discovered yet. Waiting for peer discovery...")
                else:
                    for peer_id, (ip, port) in peer.peers.items():
                        print(f"{peer_id} - {ip}:{port}")
                
            elif choice == '4':
                query = input("Enter search query: ")
                results = peer.search_files(query)
                
                if not results:
                    print("No files found matching your query.")
                else:
                    print("\nSearch Results:")
                    for i, result in enumerate(results):
                        location = "Local" if result['location'] == 'local' else f"Remote ({result['peer_id']})"
                        print(f"{i+1}. {result['filename']} - {result['filesize']} bytes - {location}")
                    
                    try:
                        selection = int(input("\nEnter number to download (0 to cancel): "))
                        if selection > 0 and selection <= len(results):
                            selected_file = results[selection-1]
                            
                            if selected_file['location'] == 'local':
                                print("File is already available locally.")
                            else:
                                destination = input(f"Enter download destination (default: {peer.shared_directory}): ")
                                if not destination:
                                    destination = peer.shared_directory
                                
                                if not os.path.exists(destination):
                                    os.makedirs(destination)
                                
                                # Download the file with Merkle tree verification
                                success = peer.download_file(
                                    selected_file['file_hash'],
                                    selected_file['peer_id'],
                                    destination
                                )
                                
                                if success:
                                    print("Download complete and verified with Merkle tree!")
                                    # Re-index files to include the newly downloaded file
                                    peer._index_files()
                                else:
                                    print("Download failed or integrity check failed.")
                    except ValueError:
                        print("Invalid selection.")
                        
            elif choice == '5':
                filepath = input("Enter path to file to upload: ")
                if not os.path.exists(filepath):
                    print("File not found.")
                    continue
                    
                print("\nKnown Peers:")
                if not peer.peers:
                    print("No peers discovered yet. Waiting for peer discovery...")
                    continue
                    
                peer_list = []
                for i, (peer_id, (ip, port)) in enumerate(peer.peers.items()):
                    if peer_id != peer.id:  # Don't show self
                        peer_list.append(peer_id)
                        print(f"{i+1}. {peer_id} - {ip}:{port}")
                
                if not peer_list:
                    print("No remote peers available.")
                    continue
                    
                try:
                    selection = int(input("\nEnter number to upload to (0 to cancel): "))
                    if selection > 0 and selection <= len(peer_list):
                        selected_peer = peer_list[selection-1]
                        
                        # Upload the file with Merkle tree verification
                        success = peer.upload_file(filepath, selected_peer)
                        
                        if success:
                            print("Upload complete and verified with Merkle tree!")
                        else:
                            print("Upload failed.")
                except ValueError:
                    print("Invalid selection.")
                
            elif choice == '6':
                print("\nFetching files from all peers...")
                all_files = peer.get_all_files()
                
                # Display local files
                print("\nLOCAL FILES:")
                print("-" * 50)
                if not all_files['local']:
                    print("No local files shared.")
                else:
                    for file in all_files['local']:
                        print(f"{file['filename']} - {file['filesize']} bytes - {file['file_hash'][:8]}...")
                
                # Display remote peers' files
                print("\nREMOTE PEERS FILES:")
                if not all_files['remote']:
                    print("No peers discovered yet or no remote files available.")
                else:
                    for peer_id, files in all_files['remote'].items():
                        print(f"\nPEER: {peer_id}")
                        print("-" * 50)
                        if not files:
                            print("No files shared by this peer.")
                        else:
                            for file in files:
                                print(f"{file['filename']} - {file['filesize']} bytes - {file['file_hash'][:8]}...")
                
            elif choice == '7':
                filepath = input("Enter path to file to verify: ")
                if not os.path.exists(filepath):
                    print("File not found.")
                    continue
                    
                chunks = chunk_file(filepath)
                merkle_hash = merkle_tree(chunks)
                
                print(f"Merkle root hash for {os.path.basename(filepath)}: {merkle_hash}")
                print("This hash can be used to verify file integrity during transfers.")
                
            elif choice == '8':
                break
                
            else:
                print("Invalid choice. Try again.")
                
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        peer.stop()
        print("Peer service stopped.")

if __name__ == "__main__":
    main()