# made by Dean Gabbai, ID 326256112
# server_sql.py version 25
# Have Fun validating this code, as I've had making it :)

import socket
import threading
import struct
import uuid
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import zlib
from Crypto.Util.Padding import unpad
import sqlite3
import datetime  # Added for handling LastSeen timestamps

# Read port from port.info
PORT = 1234  # Default port
try:
    with open('port.info', 'r') as f:
        PORT = int(f.read().strip())
except FileNotFoundError:
    print("Warning: port.info not found, using default port 1234")

HOST = ''  # Listen on all interfaces

clients = {}  # Store client data in memory
lock = threading.Lock()  # To synchronize access to clients

# Directory to store received files
RECEIVED_FILES_DIR = 'received_files'

AES_KEY_SIZE = 32      # 256-bit AES key
CLIENT_ID_SIZE = 16
NAME_SIZE = 255
IV_SIZE = 16

def init_database():
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    # Create clients table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            ID BLOB PRIMARY KEY,
            Name TEXT UNIQUE,
            PublicKey BLOB,
            LastSeen TEXT,
            AESKey BLOB
        )
    ''')
    # Create files table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            ID BLOB,
            FileName TEXT,
            PathName TEXT,
            Verified BOOLEAN,
            FOREIGN KEY(ID) REFERENCES clients(ID)
        )
    ''')
    conn.commit()
    conn.close()

def load_clients():
    conn = sqlite3.connect('defensive.db')
    c = conn.cursor()
    c.execute('SELECT ID, Name, PublicKey, AESKey FROM clients')
    rows = c.fetchall()
    with lock:
        for row in rows:
            client_id = row[0]  # BLOB
            name = row[1]       # TEXT
            public_key_data = row[2]  # BLOB
            aes_key = row[3]          # BLOB

            if public_key_data:
                public_key = RSA.import_key(public_key_data)
            else:
                public_key = None
            clients[name] = {
                'uuid': client_id,
                'public_key': public_key,
                'aes_key': aes_key,
            }
    conn.close()

def handle_client(conn, addr):
    print(f"[{addr}] New connection established.")
    db_conn = sqlite3.connect('defensive.db')
    db_cursor = db_conn.cursor()
    try:
        while True:
            # We receive a header (23 bytes)
            print(f"[{addr}] Waiting to receive header...")
            header = b''
            while len(header) < 23:
                chunk = conn.recv(23 - len(header))
                if not chunk:
                    if len(header) == 0:
                        print(f"[{addr}] Client closed the connection.")
                    else:
                        print(f"[{addr}] Connection lost while receiving header.")
                    return
                header += chunk

            # We unpack a header
            client_id = header[:CLIENT_ID_SIZE]
            version = header[16]
            code = struct.unpack('<H', header[17:19])[0]
            payload_size = struct.unpack('<I', header[19:23])[0]
            print(f"[{addr}] Received header: Version={version}, Code={code}, Payload Size={payload_size}")

            # We receive the payload
            payload = b''
            print(f"[{addr}] Receiving payload of size {payload_size}...")
            while len(payload) < payload_size:
                chunk = conn.recv(payload_size - len(payload))
                if not chunk:
                    print(f"[{addr}] Connection lost while receiving payload.")
                    return
                payload += chunk
            print(f"[{addr}] Payload received successfully.")

            # We print the protocol code received
            print(f"[{addr}] Received request with code: {code}")

            # LastSeen is updated here
            now = datetime.datetime.now().isoformat()
            client_uuid = client_id  # client_id is from the header
            db_cursor.execute('UPDATE clients SET LastSeen = ? WHERE ID = ?', (now, client_uuid))
            db_conn.commit()

            # We process the request
            if code == 825:  # Registration part
                print(f"[{addr}] Processing registration request...")
                name = payload[:NAME_SIZE].split(b'\x00', 1)[0].decode()
                print(f"[{addr}] Client name: {name}")
                with lock:
                    if name in clients:
                        # The Username exists, send an error 1601
                        response_header = struct.pack('<BHI', 3, 1601, 0)
                        conn.sendall(response_header)
                        print(f"[{addr}] Sent response with code: 1601 (Registration Failure)")
                    else:
                        client_uuid = uuid.uuid4().bytes
                        clients[name] = {
                            'uuid': client_uuid,
                            'public_key': None,
                            'aes_key': None,
                        }
                        # Insert it into database
                        db_cursor.execute('INSERT INTO clients (ID, Name, LastSeen) VALUES (?, ?, ?)',
                                          (client_uuid, name, now))
                        db_conn.commit()
                        # Send a success response 1600
                        response_payload = client_uuid
                        response_header = struct.pack('<BHI', 3, 1600,
                                                      len(response_payload))
                        conn.sendall(response_header + response_payload)
                        print(f"[{addr}] Sent response with code: 1600 (Registration Success)")
            elif code == 826:  # Send the public key
                print(f"[{addr}] Processing public key submission...")
                name = payload[:NAME_SIZE].split(b'\x00', 1)[0].decode()
                print(f"[{addr}] Client name: {name}")
                public_key_data = payload[NAME_SIZE:]
                with lock:
                    if name in clients:
                        try:
                            clients[name]['public_key'] = RSA.import_key(public_key_data)
                            # Update the new data in our database
                            db_cursor.execute('UPDATE clients SET PublicKey = ? WHERE Name = ?',
                                              (public_key_data, name))
                            db_conn.commit()
                        except ValueError as e:
                            print(f"[{addr}] Failed to import public key: {e}")
                            # Send an error response 1607
                            response_header = struct.pack('<BHI', 3, 1607, 0)
                            conn.sendall(response_header)
                            continue
                        aes_key = get_random_bytes(AES_KEY_SIZE)  # 256-bit key
                        clients[name]['aes_key'] = aes_key
                        # Update AESKey in database
                        db_cursor.execute('UPDATE clients SET AESKey = ? WHERE Name = ?',
                                          (aes_key, name))
                        db_conn.commit()
                        cipher_rsa = PKCS1_OAEP.new(clients[name]['public_key'])
                        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
                        client_uuid = clients[name]['uuid']
                        response_payload = client_uuid + encrypted_aes_key
                        response_header = struct.pack('<BHI', 3, 1602,
                                                      len(response_payload))
                        conn.sendall(response_header + response_payload)
                        print(f"[{addr}] Sent response with code: 1602 (Public Key Acknowledgment)")
                    else:
                        # send an error response 1607
                        response_header = struct.pack('<BHI', 3, 1607, 0)
                        conn.sendall(response_header)
                        print(f"[{addr}] Sent response with code: 1607 (General Error)")
            elif code == 827:  # Reconnection
                print(f"[{addr}] Processing reconnection request...")
                name = payload[:NAME_SIZE].split(b'\x00', 1)[0].decode()
                print(f"[{addr}] Client name: {name}")
                with lock:
                    if name in clients and clients[name]['public_key']:
                        aes_key = clients[name]['aes_key']
                        cipher_rsa = PKCS1_OAEP.new(clients[name]['public_key'])
                        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
                        client_uuid = clients[name]['uuid']
                        response_payload = client_uuid + encrypted_aes_key
                        response_header = struct.pack('<BHI', 3, 1605,
                                                      len(response_payload))
                        conn.sendall(response_header + response_payload)
                        print(f"[{addr}] Sent response with code: 1605 (Reconnection Success)")
                    else:
                        client_uuid = clients[name]['uuid'] if name in clients \
                                      else b'\x00'*16
                        response_payload = client_uuid
                        response_header = struct.pack('<BHI', 3, 1606,
                                                      len(response_payload))
                        conn.sendall(response_header + response_payload)
                        print(f"[{addr}] Sent response with code: 1606 (Reconnection Failure)")
            elif code == 828:  # Send file
                print(f"[{addr}] Processing file transfer...")
                # Minimum expected payload size before knowing content size
                min_expected_payload_size = (
                    4 +  # Size Content
                    4 +  # Size File Orig
                    2 + 2 +  # Packet number, total packets
                    NAME_SIZE  # Name File
                )

                if len(payload) < min_expected_payload_size:
                    print(f"[{addr}] Invalid payload size for code 828. Payload too small.")
                    # send an error response 1607
                    response_header = struct.pack('<BHI', 3, 1607, 0)
                    conn.sendall(response_header)
                    continue

                content_size = struct.unpack('<I', payload[0:4])[0]
                original_size = struct.unpack('<I', payload[4:8])[0]
                packet_num, total_packets = struct.unpack('<HH', payload[8:12])
                file_name_bytes = payload[12:12+NAME_SIZE]
                file_name = file_name_bytes.split(b'\x00', 1)[0].decode()
                content = payload[12+NAME_SIZE:]

                # Now that we know content_size, check if payload size is correct
                expected_payload_size = min_expected_payload_size + content_size
                if len(payload) != expected_payload_size:
                    print(f"[{addr}] Invalid payload size for code 828. Expected {expected_payload_size} bytes, got {len(payload)} bytes.")
                    # send an error response 1607
                    response_header = struct.pack('<BHI', 3, 1607, 0)
                    conn.sendall(response_header)
                    continue
                #----------------------------- here we will debug our output -----------------------------
                print(f"[{addr}] Content size: {content_size}, Original size: {original_size}")
                print(f"[{addr}] Packet number: {packet_num}, Total packets: {total_packets}")
                print(f"[{addr}] File name: {file_name}")
                print(f"[{addr}] Encrypted content size received: {len(content)} bytes")

                # let's find ourselves the client name based on client_id :)
                client_uuid = client_id
                name = None
                with lock:
                    for client_name, client_data in clients.items():
                        if client_data['uuid'] == client_uuid:
                            name = client_name
                            break

                if name and clients[name]['aes_key']:
                    print(f"[{addr}] Client {name} found. Proceeding with decryption.")
                    aes_key = clients[name]['aes_key']
                    # Decrypt the content using AES-CBC with zero IV
                    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=b'\x00'*IV_SIZE)
                    decrypted_content = cipher_aes.decrypt(content)
                    # de-pad the decrypted content
                    try:
                        decrypted_content = unpad(decrypted_content, AES.block_size)
                        print(f"[{addr}] Decryption and unpadding successful.")
                    except ValueError:
                        # Padding error
                        print(f"[{addr}] Padding error while decrypting the file.")
                        # send an error response 1607
                        response_header = struct.pack('<BHI', 3, 1607, 0)
                        conn.sendall(response_header)
                        continue

                    # Create directory if it doesn't exist
                    if not os.path.exists(RECEIVED_FILES_DIR):
                        os.makedirs(RECEIVED_FILES_DIR)
                        print(f"[{addr}] Created directory: {RECEIVED_FILES_DIR}")
                    # Save the file in the directory
                    file_path = os.path.join(RECEIVED_FILES_DIR, file_name)
                    with open(file_path, 'wb') as f:
                        f.write(decrypted_content[:original_size])
                    print(f"[{addr}] Saved file: {file_path}")
                    # Compute CRC
                    crc_value = zlib.crc32(
                        decrypted_content[:original_size]) & 0xffffffff
                    print(f"[{addr}] Computed CRC32: {crc_value}")

                    # Insert into files table
                    db_cursor.execute('INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)',
                                      (client_uuid, file_name, file_path, False))  # Verified is False initially
                    db_conn.commit()

                    # Send response 1603
                    response_payload = client_uuid + struct.pack('<I',
                        content_size) + file_name_bytes + struct.pack('<I',
                        crc_value)
                    response_header = struct.pack('<BHI', 3, 1603,
                                                  len(response_payload))
                    conn.sendall(response_header + response_payload)
                    print(f"[{addr}] Sent response with code: 1603 (File Received)")
                else:
                    # Error response 1607
                    print(f"[{addr}] Client not found or AES key missing.")
                    response_header = struct.pack('<BHI', 3, 1607, 0)
                    conn.sendall(response_header)
                    print(f"[{addr}] Sent response with code: 1607 (General Error)")
            elif code in (900, 901, 902):  # CRC confirmation/error
                print(f"[{addr}] Processing CRC confirmation/error with code {code}...")
                # Extract file name from payload
                file_name = payload[:NAME_SIZE].split(b'\x00', 1)[0].decode()
                # If code is 900 (CRC valid), update Verified field
                if code == 900:
                    # Set Verified = True in files table
                    db_cursor.execute('UPDATE files SET Verified = ? WHERE ID = ? AND FileName = ?',
                                      (True, client_uuid, file_name))
                    db_conn.commit()
                    print(f"[{addr}] Updated Verified status for file {file_name}")
                # Regardless of the code, send acknowledgment 1604
                client_uuid = client_id
                response_payload = client_uuid
                response_header = struct.pack('<BHI', 3, 1604,
                                              len(response_payload))
                conn.sendall(response_header + response_payload)
                print(f"[{addr}] Sent response with code: 1604 (Acknowledgment)")
            else:
                # Unknown request code, send an error 1607
                print(f"[{addr}] Unknown request code: {code}. Sending error response.")
                response_header = struct.pack('<BHI', 3, 1607, 0)
                conn.sendall(response_header)
                print(f"[{addr}] Sent response with code: 1607 (General Error)")
    except Exception as e:
        print(f"[{addr}] An error occurred: {e}")
    finally:
        db_conn.close()
        conn.close()
        print(f"[{addr}] Connection closed.")

def main():
    print("Starting server...")
    init_database()
    load_clients()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server listening on port {PORT}")
    while True:
        conn, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        threading.Thread(target=handle_client,
                         args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()