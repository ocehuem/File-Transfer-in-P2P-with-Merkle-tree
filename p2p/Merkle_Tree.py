import hashlib
import socket
import json
import os

# Merkle Tree Functions
def hash_chunk(chunk):
    return hashlib.sha256(chunk).hexdigest()

def build_tree(chunks):
    hashes = [hash_chunk(chunk) for chunk in chunks]
    tree = [hashes]
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        hashes = [hash_chunk((hashes[i] + hashes[i + 1]).encode()) for i in range(0, len(hashes), 2)]
        tree.append(hashes)
    return tree

def get_merkle_root(chunks):
    tree = build_tree(chunks)
    return tree[-1][0] if tree else None

def print_merkle_tree(tree):
    if not tree:
        print("Empty tree")
        return
    
    print("\n--- Merkle Tree Visualization ---")
    
    # Print from root (top) to leaves (bottom)
    for level in range(len(tree) - 1, -1, -1):
        level_nodes = tree[level]
        
        print(f"\nLevel {len(tree) - level - 1}:")
        for i, node in enumerate(level_nodes):
            # Truncate hashes for better visualization
            short_hash = node[:6] + "..." + node[-6:]
            print(f"  Node {i}: {short_hash}")
        
        # Print connections between levels
        if level > 0:
            print("\n  Connections:")
            child_level = tree[level - 1]
            for i in range(0, len(child_level), 2):
                if i + 1 < len(child_level):
                    print(f"  Nodes {i} and {i+1} → Node {i//2} above")
                else:
                    print(f"  Node {i} → Node {i//2} above (duplicated)")
    
    print("\n--- End of Tree Visualization ---")

# Read and Split File into Chunks
def read_file_chunks(file_path, chunk_size=1024):
    chunks = []
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                chunks.append(chunk)
        return chunks
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []


class MerkleTreePeer:
    def __init__(self, host, port, is_server=True):
        self.host = host
        self.port = port
        self.is_server = is_server
        self.socket = None
        self.file_info = None
        self.tree = None

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.is_server:
            self.socket.bind((self.host, self.port))
            self.socket.listen(1)
            print(f"Server listening on {self.host}:{self.port}")
            self.conn, self.addr = self.socket.accept()
            print(f"Connection from {self.addr}")
            return self.conn
        else:
            try:
                self.socket.connect((self.host, self.port))
                print(f"Connected to server at {self.host}:{self.port}")
                return self.socket
            except ConnectionRefusedError:
                print("Connection failed. Is the server running?")
                return None

    def send_data(self, data, conn=None):
        if conn is None:
            conn = self.socket
        try:
            conn.sendall(json.dumps(data).encode('utf-8'))
        except Exception as e:
            print(f"Error sending data: {e}")

    def receive_data(self, conn=None):
        if conn is None:
            conn = self.socket
        try:
            data = conn.recv(1024 * 1024)
            if not data:
                return None
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f"Error receiving data: {e}")
            return None

    def prepare_file(self, file_path):
        chunks = read_file_chunks(file_path)
        if not chunks:
            print("Failed to read file.")
            return False
        self.tree = build_tree(chunks)
        self.file_info = {
            "root": self.tree[-1][0] if self.tree else None,
            "chunks": chunks
        }
        return True

    def print_tree(self):
        if self.tree:
            print_merkle_tree(self.tree)
        else:
            print("No Merkle tree has been built yet.")

    def sender_protocol(self, conn):
        self.send_data({"type": "merkle_root", "root": self.file_info["root"]}, conn)
        response = self.receive_data(conn)
        if not response or response.get("type") != "merkle_root_result":
            print("Invalid response received for Merkle root comparison")
            return
        if response.get("match"):
            print("Integrity check passed! Files are identical.")
        else:
            print("Integrity check failed. Files are different.")

    def receiver_protocol(self, conn):
        request = self.receive_data(conn)
        if not request or request.get("type") != "merkle_root":
            print("Invalid Merkle root request received")
            return
        remote_root = request.get("root")
        print(f"Received Merkle root: {remote_root}")
        match = (remote_root == self.file_info["root"])
        self.send_data({"type": "merkle_root_result", "match": match}, conn)
        if match:
            print("Integrity check passed! Files are identical.")
        else:
            print("Integrity check failed. Files are different.")

# Main Execution
if __name__ == "__main__":
    print("Merkle Tree P2P File Integrity Checker")
    print("1. Send file for comparison")
    print("2. Receive file for comparison")
    print("3. Build and visualize Merkle tree for a file")
    choice = input("Enter your choice (1/2/3): ")

    if choice in ("1", "2", "3"):
        file_path = input("Enter file path: ")
        
    if choice == "1":
        host = input("Enter receiver's host (default: localhost): ") or "localhost"
        port = int(input("Enter receiver's port (default: 12345): ") or "12345")
        
        peer = MerkleTreePeer(host, port, is_server=False)
        conn = peer.connect()
        if not conn:
            exit(1)
        if not peer.prepare_file(file_path):
            exit(1)
            
        # Ask if user wants to see the tree
        if input("Would you like to visualize the Merkle tree before sending? (y/n): ").lower() == 'y':
            peer.print_tree()
            
        peer.sender_protocol(conn)

    elif choice == "2":
        host = input("Enter your host (default: localhost): ") or "localhost"
        port = int(input("Enter your port (default: 12345): ")) or "12345"

        peer = MerkleTreePeer(host, port, is_server=True)
        conn = peer.connect()
        if not conn:
            exit(1)
        if not peer.prepare_file(file_path):
            exit(1)
            
        # Ask if user wants to see the tree
        if input("Would you like to visualize the Merkle tree before receiving? (y/n): ").lower() == 'y':
            peer.print_tree()
            
        peer.receiver_protocol(conn)

    elif choice == "3":
        peer = MerkleTreePeer("localhost", 0, is_server=False) 
        if peer.prepare_file(file_path):
            print(f"Successfully built Merkle tree for file: {file_path}")
            print(f"Merkle Root: {peer.file_info['root']}")
            peer.print_tree()
            
            # Option to save tree info to file
            if input("Would you like to save the Merkle tree details to a file? (y/n): ").lower() == 'y':
                output_file = input("Enter output file name (default: merkle_tree_info.txt): ") or "merkle_tree_info.txt"
                try:
                    with open(output_file, 'w') as f:
                        f.write(f"File: {file_path}\n")
                        f.write(f"Merkle Root: {peer.file_info['root']}\n\n")
                        f.write("Tree Structure:\n")
                        for level in range(len(peer.tree) - 1, -1, -1):
                            f.write(f"\nLevel {len(peer.tree) - level - 1}:\n")
                            for i, node in enumerate(peer.tree[level]):
                                f.write(f"  Node {i}: {node}\n")
                    print(f"Tree details saved to {output_file}")
                except Exception as e:
                    print(f"Error saving tree details: {e}")
    else:
        print("Invalid choice.")
