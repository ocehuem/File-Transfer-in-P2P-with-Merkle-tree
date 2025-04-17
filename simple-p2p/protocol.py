import json
import enum
import time
from dataclasses import dataclass, field

class MessageType(enum.Enum):
    PEER_ANNOUNCE = 'peer_announce'    # Announce peer presence
    FILE_QUERY = 'file_query'          # Query for files
    QUERY_RESPONSE = 'query_response'  # Response to query
    FILE_REQUEST = 'file_request'      # Request a file
    FILE_RESPONSE = 'file_response'    # Response to file request

@dataclass
class Message:
    type: MessageType
    sender: str
    content: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def to_json(self):
        """Convert message to JSON string"""
        data = {
            'type': self.type.value,
            'sender': self.sender,
            'content': self.content,
            'timestamp': self.timestamp
        }
        return json.dumps(data)
    
    @classmethod
    def from_json(cls, json_str):
        """Create message from JSON string"""
        data = json.loads(json_str)
        return cls(
            type=MessageType(data['type']),
            sender=data['sender'],
            content=data['content'],
            timestamp=data['timestamp']
        )
