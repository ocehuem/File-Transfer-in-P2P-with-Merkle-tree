import json
import enum

class MessageType(enum.Enum):
    PEER_ANNOUNCE = "peer_announce"
    FILE_REQUEST = "file_request"
    FILE_RESPONSE = "file_response"
    FILE_DATA_REQUEST = "file_data_request"
    FILE_QUERY = "file_query"
    QUERY_RESPONSE = "query_response"
    GET_ALL_FILES = "get_all_files"
    ALL_FILES_RESPONSE = "all_files_response"

class Message:
    """
    Message format for P2P communication
    """
    def __init__(self, type, sender, content=None):
        self.type = type
        self.sender = sender
        self.content = content or {}
        
    def to_json(self):
        """Convert message to JSON string"""
        return json.dumps({
            'type': self.type.value if isinstance(self.type, MessageType) else self.type,
            'sender': self.sender,
            'content': self.content
        })
    
    @classmethod
    def from_json(cls, json_str):
        """Create message from JSON string"""
        data = json.loads(json_str)
        return cls(
            type=MessageType(data['type']) if isinstance(data['type'], str) else data['type'],
            sender=data['sender'],
            content=data.get('content', {})
        )