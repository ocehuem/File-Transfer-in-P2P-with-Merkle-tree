import socket
import time
import threading
from protocol import Message, MessageType
from config import DISCOVERY_PORT, BUFFER_SIZE

class PeerDiscovery:
    """Handles peer discovery using UDP broadcasts"""
    
    def __init__(self, peer_id, port, peer_list):
        self.peer_id = peer_id
        self.port = port
        self.peer_list = peer_list  # Reference to parent's peer list
        self.running = False
        
        # Create UDP socket for discovery
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.bind(('0.0.0.0', DISCOVERY_PORT))
        
    def start(self):
        """Start the discovery service"""
        self.running = True
        
        # Start listener thread
        self.listener_thread = threading.Thread(target=self._listen_loop)
        self.listener_thread.daemon = True
        self.listener_thread.start()
        
        # Start broadcast thread
        self.broadcast_thread = threading.Thread(target=self._broadcast_loop)
        self.broadcast_thread.daemon = True
        self.broadcast_thread.start()
        
    def stop(self):
        """Stop the discovery service"""
        self.running = False
        self.socket.close()
        
    def _listen_loop(self):
        """Listen for peer announcements"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(BUFFER_SIZE)
                message = Message.from_json(data.decode('utf-8'))
                
                if message.type == MessageType.PEER_ANNOUNCE and message.sender != self.peer_id:
                    # Add peer to known peers
                    peer_id = message.sender
                    peer_port = message.content.get('port', self.port)
                    self.peer_list[peer_id] = (addr[0], peer_port)
                    print(f"Discovered peer: {peer_id} at {addr[0]}:{peer_port}")
            except Exception as e:
                if self.running:  # Only print if not caused by stopping
                    print(f"Discovery listening error: {e}")
                
    def _broadcast_loop(self):
        """Periodically broadcast presence"""
        while self.running:
            try:
                # Broadcast presence
                announce_msg = Message(
                    type=MessageType.PEER_ANNOUNCE,
                    sender=self.peer_id,
                    content={
                        'port': self.port,
                        'timestamp': time.time()
                    }
                )
                self.socket.sendto(
                    announce_msg.to_json().encode('utf-8'), 
                    ('<broadcast>', DISCOVERY_PORT)
                )
                time.sleep(30)  # Announce every 30 seconds
            except Exception as e:
                if self.running:  # Only print if not caused by stopping
                    print(f"Discovery broadcast error: {e}")
                time.sleep(5)  # Wait before retrying
