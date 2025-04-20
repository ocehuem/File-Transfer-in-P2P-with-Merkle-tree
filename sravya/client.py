import os
import sys
import time
import argparse
import socket
import json
import hashlib
import threading
from datetime import datetime

class Peer:
    def __init__(self, shared_directory='./shared', port=8000):
        self.shared_directory = shared_directory
        self.port = port
        self.id = hashlib.sha256(f"{socket.gethostname()}:{port}:{datetime.now()}".encode()).hexdigest()[:12]
        self.peers = {}  # {peer_id: (ip, port)}
        self.available_files = {}  # {file_hash: filepath}
        self.running = False
        
        # Create shared directory if it doesn't exist
        if not os.path.exists(shared_directory):
            os.makedirs(shared_directory)
            
        # Index local files
        self.index_local_files()
    
    def start(self):
        """Start the peer services"""
        self.running = True
        print(f"Peer {self.id} starting on port {self.port}")
        
        # Start peer discovery in a separate thread
        self.discovery_thread = threading.Thread(target=self._run_discovery)
        self.discovery_thread.daemon = True
        self.discovery_thread.start()
        
        # Start server socket to accept incoming connections
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.server_thread = threading.Thread(target=self._server_loop)
            self.server_thread.daemon = True
            self.server_thread.start()
        except Exception as e:
            print(f"Error starting server: {e}")

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
            data = client_sock.recv(8192)
            if not data:
                return
                
            request = json.loads(data.decode())
            request_type = request.get("type")
            
            if request_type == "file_list_request":
                # Send local file list
                local_files = []
                for file_hash, filepath in self.available_files.items():
                    filename = os.path.basename(filepath)
                    local_files.append({
                        'filename': filename,
                        'filesize': os.path.getsize(filepath),
                        'file_hash': file_hash
                    })
                
                response = {
                    "status": "ok",
                    "files": local_files
                }
                client_sock.sendall(json.dumps(response).encode())
                
            elif request_type == "file_request":
                # Handle file metadata request
                file_hash = request.get("file_hash")
                if file_hash in self.available_files:
                    filepath = self.available_files[file_hash]
                    filename = os.path.basename(filepath)
                    filesize = os.path.getsize(filepath)
                    merkle_root, level_hashes = self.calculate_merkle_root(filepath)
                    
                    response = {
                        "status": "ok",
                        "filename": filename,
                        "filesize": filesize,
                        "merkle_root": merkle_root,
                        "level_hashes": level_hashes  # Include full merkle tree data
                    }
                else:
                    response = {
                        "status": "error",
                        "message": "File not found"
                    }
                client_sock.sendall(json.dumps(response).encode())
                
            elif request_type == "file_data_request":
                # Handle actual file transfer
                file_hash = request.get("file_hash")
                if file_hash in self.available_files:
                    filepath = self.available_files[file_hash]
                    
                    # First send a simple "ready" response
                    response = {"status": "ready"}
                    client_sock.sendall(json.dumps(response).encode())
                    
                    # Small delay to ensure client is ready
                    time.sleep(0.5)
                    
                    # Send the file in chunks
                    with open(filepath, 'rb') as f:
                        while chunk := f.read(4096):  # Use smaller chunks
                            client_sock.sendall(chunk)
                            time.sleep(0.01)  # Small delay between chunks
                else:
                    response = {
                        "status": "error",
                        "message": "File not found"
                    }
                    client_sock.sendall(json.dumps(response).encode())
                    
        except Exception as e:
            print(f"Error handling client {client_addr}: {e}")
        finally:
            client_sock.close()

    def _run_discovery(self):
        """Periodically discover peers"""
        while self.running:
            self.discover_peers()
            time.sleep(30)  # Discover peers every 30 seconds
    
    def discover_peers(self):
        """Basic peer discovery - simplified for this implementation"""
        # In a real implementation, this would use UDP broadcast or a discovery server
        print("Searching for peers...")
        # Just simulate for now - using the manually added peers
    
    def stop(self):
        """Stop the peer service"""
        self.running = False
        if hasattr(self, 'server_socket'):
            try:
                self.server_socket.close()
            except:
                pass
        print("Peer service stopped.")
    
    def index_local_files(self):
        """Index all files in the shared directory"""
        if not os.path.exists(self.shared_directory):
            return
            
        for root, _, files in os.walk(self.shared_directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                file_hash = self.calculate_file_hash(filepath)
                self.available_files[file_hash] = filepath
    
    def calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def search_files(self, query):
        """Search for files matching the query"""
        results = []
        
        # Search local files
        for file_hash, filepath in self.available_files.items():
            filename = os.path.basename(filepath)
            if query.lower() in filename.lower():
                results.append({
                    'filename': filename,
                    'filesize': os.path.getsize(filepath),
                    'file_hash': file_hash,
                    'location': 'local',
                    'peer_id': self.id
                })
        
        # Search remote files
        for peer_id, (ip, port) in self.peers.items():
            if peer_id != self.id:  # Skip self
                remote_files = self.get_peer_files(peer_id)
                for file_info in remote_files:
                    if query.lower() in file_info['filename'].lower():
                        results.append({
                            'filename': file_info['filename'],
                            'filesize': file_info['filesize'],
                            'file_hash': file_info['file_hash'],
                            'location': 'remote',
                            'peer_id': peer_id
                        })
                    
        return results
    
    def get_peer_files(self, peer_id):
        """Get files from a specific peer"""
        # If it's the local peer, return local files
        if peer_id == self.id:
            local_files = []
            for file_hash, filepath in self.available_files.items():
                filename = os.path.basename(filepath)
                local_files.append({
                    'filename': filename,
                    'filesize': os.path.getsize(filepath),
                    'file_hash': file_hash
                })
            return local_files
        
        # For remote peers
        try:
            # Check if we know this peer
            if peer_id not in self.peers:
                print(f"Unknown peer: {peer_id}")
                return []
            
            peer_ip, peer_port = self.peers[peer_id]
            
            # Create a socket connection to the peer
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(5)  # 5 second timeout
            
            try:
                # Try to connect to the peer
                client_socket.connect((peer_ip, peer_port))
                
                # Send file list request
                request = {
                    "type": "file_list_request"
                }
                client_socket.sendall(json.dumps(request).encode())
                
                # Receive response
                response = json.loads(client_socket.recv(8192).decode())
                
                if response.get("status") == "ok":
                    return response.get("files", [])
                else:
                    print(f"Error getting files from peer {peer_id}: {response.get('message', 'Unknown error')}")
                    return []
                    
            except socket.timeout:
                print(f"Connection to peer {peer_id} timed out")
                return []
            except ConnectionRefusedError:
                print(f"Connection to peer {peer_id} refused")
                return []
            except Exception as e:
                print(f"Error communicating with peer {peer_id}: {str(e)}")
                return []
            finally:
                client_socket.close()
                
        except Exception as e:
            print(f"Error getting files from peer {peer_id}: {str(e)}")
            return []
    
    def get_all_peer_files(self):
        """Get files from all known peers"""
        all_files = {
            'local': [],  # Local files
            'peers': {}   # Remote peers' files
        }
        
        # Add local files
        for file_hash, filepath in self.available_files.items():
            filename = os.path.basename(filepath)
            all_files['local'].append({
                'filename': filename,
                'filesize': os.path.getsize(filepath),
                'file_hash': file_hash
            })
        
        # Add remote peers' files
        for peer_id, (ip, port) in self.peers.items():
            if peer_id != self.id:  # Skip self
                peer_files = self.get_peer_files(peer_id)
                if peer_files:
                    all_files['peers'][peer_id] = peer_files
                    
        return all_files
    
    def chunk_file(self, file_path, chunk_size=1024):
        """Break a file into chunks for building the merkle tree"""
        chunks = []
        chunk_data = []  # Store actual chunk data for verification
        
        with open(file_path, 'rb') as f:
            chunk_num = 0
            while chunk := f.read(chunk_size):
                # Store the actual binary chunk for potential verification
                chunk_data.append(chunk)
                # Convert binary data to string for hashing
                chunk_str = chunk.decode('utf-8', errors='ignore')
                chunks.append(chunk_str)
                chunk_num += 1
        
        print(f"\nMerkle Tree - Chunked file into {len(chunks)} chunks")
        return chunks if chunks else [""], chunk_data if chunk_data else [b""]
    
    def merkle_tree(self, chunks, level=0):
        """Create a Merkle tree from file chunks and return the root hash with level-wise logs"""
        # Print level information
        indent = "  " * level
        print(f"{indent}Level {level}: Processing {len(chunks)} chunks/nodes")
        
        if len(chunks) == 1:
            node_hash = hashlib.sha256(chunks[0].encode()).hexdigest()
            print(f"{indent}Level {level}: Leaf node hash: {node_hash[:8]}...")
            return node_hash, {level: [node_hash]}
        
        # Calculate hashes at this level
        current_level_hashes = []
        for chunk in chunks:
            if isinstance(chunk, str):
                # This is a leaf node (actual data chunk)
                h = hashlib.sha256(chunk.encode()).hexdigest()
            else:
                # This is already a hash from previous iteration
                h = chunk
            current_level_hashes.append(h)
            
        # Print all hashes at current level
        print(f"{indent}Level {level}: Current level hashes:")
        for i, h in enumerate(current_level_hashes):
            print(f"{indent}  Node {i+1}: {h[:8]}...")
        
        # Prepare next level nodes
        next_level = []
        i = 0
        while i < len(current_level_hashes):
            if i + 1 < len(current_level_hashes):
                # Combine pair of hashes
                combined = current_level_hashes[i] + current_level_hashes[i+1]
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                print(f"{indent}Level {level}: Combining {current_level_hashes[i][:8]}... + {current_level_hashes[i+1][:8]}... → {parent_hash[:8]}...")
                next_level.append(parent_hash)
            else:
                # Odd number of nodes, promote the last one
                next_level.append(current_level_hashes[i])
                print(f"{indent}Level {level}: Promoting single node {current_level_hashes[i][:8]}...")
            i += 2
        
        # Recursively build the next level
        root_hash, level_hashes = self.merkle_tree(next_level, level + 1)
        
        # Add current level hashes to the level_hashes dictionary
        level_hashes[level] = current_level_hashes
        
        return root_hash, level_hashes
    
    def calculate_merkle_root(self, filepath, chunk_size=1024):
        """Calculate the Merkle tree root hash for a file with level-wise logging"""
        print(f"\n======== Building Merkle Tree for {os.path.basename(filepath)} ========")
        chunks, _ = self.chunk_file(filepath, chunk_size)
        root_hash, level_hashes = self.merkle_tree(chunks)
        
        # Summarize the Merkle tree
        print("\n======== Merkle Tree Summary ========")
        print(f"Total levels: {len(level_hashes)}")
        for level, hashes in sorted(level_hashes.items(), reverse=True):
            if level == max(level_hashes.keys()):
                print(f"Level {level} (Root): {hashes[0]}")
            else:
                print(f"Level {level}: {len(hashes)} nodes")
        print("===================================\n")
        
        return root_hash, level_hashes
    
    def compare_merkle_trees(self, source_level_hashes, calculated_level_hashes):
        """Compare two Merkle trees and identify corrupted chunks"""
        # First, confirm we have the same levels
        if set(source_level_hashes.keys()) != set(calculated_level_hashes.keys()):
            print("Error: The Merkle trees have different structures.")
            return False, []
        
        # Get the lowest level (leaf nodes/chunks)
        leaf_level = min(source_level_hashes.keys())
        
        # Compare the hashes at leaf level (representing file chunks)
        source_leaf_hashes = source_level_hashes[leaf_level]
        calc_leaf_hashes = calculated_level_hashes[leaf_level]
        
        # Check if we have the same number of leaf nodes
        if len(source_leaf_hashes) != len(calc_leaf_hashes):
            print(f"Error: Different number of chunks. Expected {len(source_leaf_hashes)}, got {len(calc_leaf_hashes)}")
            return False, []
        
        # Find corrupted chunks
        corrupted_chunks = []
        for i, (source_hash, calc_hash) in enumerate(zip(source_leaf_hashes, calc_leaf_hashes)):
            if source_hash != calc_hash:
                corrupted_chunks.append(i)
        
        if corrupted_chunks:
            return False, corrupted_chunks
        else:
            return True, []
    
    def download_file(self, file_hash, peer_id, destination):
        """Download a file from a peer with Merkle tree verification"""
        if peer_id == self.id:
            print("File is already available locally.")
            return True
        
        if peer_id not in self.peers:
            print(f"Unknown peer: {peer_id}")
            return False
            
        peer_ip, peer_port = self.peers[peer_id]
        print(f"Connecting to peer {peer_id} at {peer_ip}:{peer_port}...")
        
        try:
            # Connect to the peer
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(30)  # Longer timeout for file transfers
            client_socket.connect((peer_ip, peer_port))
            
            # Send file request
            request = {
                "type": "file_request",
                "file_hash": file_hash
            }
            client_socket.sendall(json.dumps(request).encode())
            
            # Receive response with file metadata
            response_data = client_socket.recv(8192)
            response = json.loads(response_data.decode())
            
            if response.get("status") != "ok":
                print(f"Peer reported error: {response.get('message', 'Unknown error')}")
                return False
                
            filename = response.get("filename")
            filesize = response.get("filesize")
            merkle_root = response.get("merkle_root")
            source_level_hashes = response.get("level_hashes")
            
            # Check if level_hashes is None and handle it appropriately
            if source_level_hashes is None:
                print("Warning: No Merkle tree data received from peer. Will not be able to verify specific corrupted chunks.")
                source_level_hashes = {}  # Initialize as empty dict to avoid NoneType error
            else:
                # Convert string keys back to integers
                source_level_hashes = {int(k): v for k, v in source_level_hashes.items()}
            
            print(f"Downloading {filename} ({filesize} bytes)...")
            print(f"Expected Merkle root: {merkle_root}")
            
            # Create a new socket for the file data transfer
            data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_socket.settimeout(60)  # Longer timeout for file transfers
            data_socket.connect((peer_ip, peer_port))
            
            # Request the file data
            data_request = {
                "type": "file_data_request",
                "file_hash": file_hash
            }
            data_socket.sendall(json.dumps(data_request).encode())
            
            # Get the "ready" response
            ready_response = data_socket.recv(8192)
            ready_data = json.loads(ready_response.decode())
            
            if ready_data.get("status") != "ready":
                print(f"Peer not ready to send file: {ready_data.get('message', 'Unknown error')}")
                return False
            
            # Receive file data
            destination_path = os.path.join(destination, filename)
            with open(destination_path, 'wb') as f:
                bytes_received = 0
                while bytes_received < filesize:
                    try:
                        chunk = data_socket.recv(4096)  # Use smaller chunks
                        if not chunk:
                            break
                        f.write(chunk)
                        bytes_received += len(chunk)
                        print(f"Progress: {bytes_received}/{filesize} bytes ({bytes_received/filesize*100:.1f}%)", end="\r")
                    except socket.timeout:
                        break
                print()  # New line after progress
            
            # Close data socket
            data_socket.close()
            
            if bytes_received < filesize:
                print(f"Incomplete download: {bytes_received}/{filesize} bytes received")
                return False
                
            # Calculate the merkle tree of the downloaded file
            calculated_merkle_root, calculated_level_hashes = self.calculate_merkle_root(destination_path)
            
            # Verify the merkle root
            print("\n======== Merkle Tree Verification ========")
            print(f"Expected Merkle root: {merkle_root}")
            print(f"Calculated Merkle root: {calculated_merkle_root}")
            
            if calculated_merkle_root == merkle_root:
                print("✓ VERIFICATION SUCCESSFUL: File integrity verified using Merkle tree!")
                return True
            else:
                print("✗ VERIFICATION FAILED: File integrity check failed. The file may be corrupted.")
                
                # Check which chunks are corrupted only if we have source_level_hashes
                if source_level_hashes and len(source_level_hashes) > 0:
                    integrity_ok, corrupted_chunks = self.compare_merkle_trees(source_level_hashes, calculated_level_hashes)
                    
                    if not integrity_ok:
                        print(f"\n⚠️ Found {len(corrupted_chunks)} corrupted chunks:")
                        for chunk_index in corrupted_chunks:
                            print(f"  - Chunk #{chunk_index+1} is corrupted")
                        
                        # Get the chunk size used in the merkle tree creation
                        chunk_size = 1024  # Default chunk size
                        
                        # Re-read the file chunks to show specifically which parts are corrupted
                        chunks, chunk_data = self.chunk_file(destination_path, chunk_size)
                        
                        for chunk_index in corrupted_chunks:
                            if chunk_index < len(chunks):
                                start_byte = chunk_index * chunk_size
                                end_byte = start_byte + len(chunk_data[chunk_index])
                                print(f"  - Corrupted data at bytes {start_byte}-{end_byte-1}")
                else:
                    print("Unable to pinpoint corrupted chunks: No detailed Merkle tree data available")
                
                return False
                
        except Exception as e:
            print(f"Error downloading file: {e}")
            return False
        finally:
            client_socket.close()

##############################################################
##############################################
####################################################
def main():
    parser = argparse.ArgumentParser(description='Simple P2P File Sharing with Merkle Tree Verification')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on')
    parser.add_argument('--directory', type=str, default='./shared', help='Directory to share files from')
    args = parser.parse_args()
    
    # Create and start the peer
    peer = Peer(shared_directory=args.directory, port=args.port)
    peer.start()
    
    # For testing - manually add another peer
    test_peer_ip = input("Enter another peer's IP (leave empty for solo mode): ")
    if test_peer_ip:
        test_peer_port = int(input("Enter peer's port (default 8000): ") or "8000")
        test_peer_id = "test_peer_123"  # In real implementation, this would come from discovery
        peer.peers[test_peer_id] = (test_peer_ip, test_peer_port)
        print(f"Added test peer: {test_peer_id} at {test_peer_ip}:{test_peer_port}")

    # Add self to peers list
    peer.peers[peer.id] = ('127.0.0.1', peer.port)
    
    print("\nSimple P2P File Sharing with Merkle Tree Verification")
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
            print("5. View all peer files")
            print("6. Verify file integrity")
            print("7. Simulate corrupted file transfer (test)")
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
                                else:
                                    print("Download failed or integrity check failed.")
                    except ValueError:
                        print("Invalid selection.")
                
            elif choice == '5':
                print("\nFetching files from all peers...")
                all_files = peer.get_all_peer_files()
                
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
                if not all_files['peers']:
                    print("No peers discovered yet. Waiting for peer discovery...")
                else:
                    for peer_id, files in all_files['peers'].items():
                        print(f"\nPEER: {peer_id}")
                        print("-" * 50)
                        for file in files:
                            print(f"{file['filename']} - {file['filesize']} bytes - {file['file_hash'][:8]}...")
            elif choice == '6':
                print("\nVerify file integrity using Merkle tree")
                filepath = input("Enter the path to the file to verify: ")
                
                if not os.path.exists(filepath):
                    print("File does not exist.")
                else:
                    merkle_root, level_hashes = peer.calculate_merkle_root(filepath)
                    print(f"Merkle root hash: {merkle_root}")
                    print("File integrity can be verified by comparing this Merkle root hash with the original.")
            
            elif choice == '7':
                print("\nSimulate corrupted file transfer (test)")
                filepath = input("Enter the path to a file to test corruption detection: ")
                
                if not os.path.exists(filepath):
                    print("File does not exist.")
                    continue
                
                # Create a copy of the file
                filename = os.path.basename(filepath)
                corrupted_filepath = os.path.join(os.path.dirname(filepath), f"corrupted_{filename}")
                
                # Copy the file
                with open(filepath, 'rb') as src, open(corrupted_filepath, 'wb') as dst:
                    data = src.read()
                    dst.write(data)
                
                # Calculate original Merkle tree
                merkle_root, level_hashes = peer.calculate_merkle_root(filepath)
                print(f"Original Merkle root hash: {merkle_root}")
                
                # Corrupt a random chunk in the copied file
                try:
                    chunks, chunk_data = peer.chunk_file(corrupted_filepath)
                    chunk_size = 1024  # Default chunk size
                    
                    # Choose a chunk to corrupt
                    if len(chunks) > 0:
                        corrupt_index = int(input(f"Enter chunk number to corrupt (1-{len(chunks)}): ")) - 1
                        
                        if 0 <= corrupt_index < len(chunks):
                            # Corrupt the file at the specified chunk
                            with open(corrupted_filepath, 'r+b') as f:
                                f.seek(corrupt_index * chunk_size)
                                # Write some corrupted data
                                corrupted_data = b'X' * min(chunk_size, 100)  # Corrupt up to 100 bytes
                                f.write(corrupted_data)
                            
                            print(f"Corrupted chunk #{corrupt_index+1} in file: {corrupted_filepath}")
                            
                            # Calculate new Merkle tree for corrupted file
                            corrupted_merkle_root, corrupted_level_hashes = peer.calculate_merkle_root(corrupted_filepath)
                            print(f"Corrupted file's Merkle root hash: {corrupted_merkle_root}")
                            # Compare the Merkle trees to detect corrupted chunks
                            print("\n======== Merkle Tree Verification ========")
                            print(f"Original Merkle root: {merkle_root}")
                            print(f"Corrupted file Merkle root: {corrupted_merkle_root}")
                            
                            if corrupted_merkle_root == merkle_root:
                                print("Unexpected: Merkle roots are identical despite corruption!")
                            else:
                                print("✗ VERIFICATION FAILED: Merkle roots differ as expected due to corruption")
                                
                                # Find the corrupted chunks
                                integrity_ok, corrupted_chunks = peer.compare_merkle_trees(level_hashes, corrupted_level_hashes)
                                
                                if not integrity_ok:
                                    print(f"\n⚠️ Found {len(corrupted_chunks)} corrupted chunks:")
                                    for chunk_index in corrupted_chunks:
                                        print(f"  - Chunk #{chunk_index+1} is corrupted")
                                        
                                    # Show byte ranges for corrupted chunks
                                    for chunk_index in corrupted_chunks:
                                        start_byte = chunk_index * chunk_size
                                        # Calculate end byte based on actual chunk data
                                        chunk_bytes = min(chunk_size, os.path.getsize(corrupted_filepath) - start_byte)
                                        end_byte = start_byte + chunk_bytes
                                        print(f"  - Corrupted data at bytes {start_byte}-{end_byte-1}")
                        else:
                            print(f"Invalid chunk index. Must be between 1 and {len(chunks)}")
                    else:
                        print("File has no chunks (empty file?)")
                except Exception as e:
                    print(f"Error during corruption simulation: {e}")
                    
            elif choice == '8':
                break
                
            else:
                print("Invalid choice. Please try again.")
                
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        peer.stop()

if __name__ == "__main__":
    main()