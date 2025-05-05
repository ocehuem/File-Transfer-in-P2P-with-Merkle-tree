# Simple P2P File Sharing

A peer-to-peer file sharing application that uses a direct file transfer approach without chunking files.

## Features

- **Direct File Transfer**: Unlike traditional P2P applications that break files into chunks, this system transfers complete files from a single peer.
- **Peer Discovery**: Automatic discovery of other peers on the local network.
- **File Search**: Search for files across all connected peers.
- **Simple UI**: Easy-to-use command-line interface.

## Requirements

- Python 3.7+
- No external dependencies (uses only standard library)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/simple-p2p.git
   cd simple-p2p
   ```

2. Run the application:
   
   cd web
   python main.py

   click on the peers you want to open you can see the clients running onn the terminals opened

   
   python client.py --port 8000 --directory ./shared
   

## Usage

Once the application is running, you'll see a menu with options:

1. **Search for files**: Search for files across all peers
2. **List local files**: View files in your shared directory
3. **List known peers**: See other peers on the network
4. **Download a file**: Download a file from another peer
5. **Quit**: Exit the application

## How It Works

### Peer Discovery

Peers announce themselves via UDP broadcasts on the local network. Each peer maintains a list of known peers.

### File Sharing

1. When a client requests a file, it first searches for the file across all known peers.
2. When a peer with the requested file is found, a direct TCP connection is established.
3. The file is transferred in its entirety from the provider to the requester.
4. Once the transfer is complete, the file is added to the requester's shared directory.

### Advantages Over Chunking

- Simpler implementation
- More controlled transfers
- Easier to track and verify file integrity
- Less overhead from managing multiple connections

## License

This project is licensed under the MIT License - see the LICENSE file for details.
