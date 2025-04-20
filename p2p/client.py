import os
import sys
import time
import argparse
from peer import Peer

def main():
    parser = argparse.ArgumentParser(description='Simple P2P File Sharing')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on')
    parser.add_argument('--directory', type=str, default='./shared', help='Directory to share files from')
    args = parser.parse_args()
    
    # Create and start the peer
    peer = Peer(shared_directory=args.directory, port=args.port)
    peer.start()
    
    print("\nSimple P2P File Sharing")
    print("======================")
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
            print("6. Quit")
            
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
                                
                                # Download the file
                                success = peer.download_file(
                                    selected_file['file_hash'],
                                    selected_file['peer_id'],
                                    destination
                                )
                                
                                if success:
                                    print("Download complete!")
                                else:
                                    print("Download failed.")
                    except ValueError:
                        print("Invalid selection.")
                
            elif choice == '5':
                print("\nFetching files from all peers...")
                all_files = peer.get_all_peer_files()
                
                if not all_files:
                    print("No files found in the network.")
                else:
                    for peer_id, files in all_files.items():
                        peer_type = "LOCAL" if peer_id == peer.id else f"REMOTE"
                        print(f"\n{peer_type} PEER: {peer_id}")
                        print("-" * 50)
                        
                        if not files:
                            print("No files shared by this peer.")
                        else:
                            for file in files:
                                print(f"{file['filename']} - {file['filesize']} bytes - {file['file_hash'][:8]}...")
                
            elif choice == '6':
                break
                
            else:
                print("Invalid choice. Please try again.")
                
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        peer.stop()
        print("Goodbye!")

if __name__ == "__main__":
    main()