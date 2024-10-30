# 🛡️ Defensive Systems Programming Final Project - OUI

### Author: Dean Gabbai (ID 326256112) - Version 25

👋 Welcome to the final project of the **Defensive Systems Programming** course at **OUI**! This project involves creating a secure client-server application for encrypted file transfer, showcasing the implementation of defensive coding practices in both C++ (client) and Python (server). Let's dive in! 🚀

---

### 🔍 Overview

The goal of this project is to develop a secure file transfer protocol between a client and server. The client is implemented in **C++** while the server is implemented in **Python**. The server is responsible for managing registered users, handling encryption keys, and receiving files from clients. Key features include **encrypted communication** 🔒, **file integrity verification** ✅, and **multi-user support** 👥.

- **Client Language**: C++ 🖥️
- **Server Language**: Python (version 3.12.1) 🐍
- **Encryption Libraries**: Crypto++ (C++), PyCryptodome (Python)

The client initiates contact, performs a secure key exchange, and sends encrypted files, while the server processes these requests and stores the files in a secure manner. Multi-user support is enabled using Python threading.

### 🏗️ Architecture Overview

1. **Client (C++17)**
   - 🖥️ The client application, developed in **C++**, runs in batch mode and reads server connection information from a `transfer.info` file. The client uses the **Crypto++** library for encryption tasks.
   - **🔑 RSA Key Exchange**: During initial contact, the client generates an RSA public/private key pair and sends the public key to the server.
   - **🔒 AES Encryption**: The server responds with an encrypted **AES** key, which the client uses to encrypt the file to be sent.
   - **✅ CRC32 Verification**: After transferring a file, the client calculates a CRC32 checksum for file integrity and verifies it with the server.

2. **Server (Python 3.12.1)**
   - 🐍 The server, written in **Python**, handles multiple clients concurrently using the `threading` module.
   - 📂 It uses an SQLite database (`defensive.db`) to store client information and received files, ensuring data persistence even after the server is restarted.
   - **🔑 AES Key Management**: The server generates an AES key for each client and stores it in the database.

---

### 📁 Project Files

- **`client.cpp`**: The main C++ implementation of the client, which handles all operations from registration to secure file transfer.
- **`client.h`**: Header file defining the constants, functions, and protocol codes used by the client.
- **`server_sql.py`**: The Python server implementation, responsible for managing clients, handling file uploads, and updating the SQLite database.

---

### 🌟 Key Features

1. **🔐 Encrypted Communication**
   - The protocol uses **RSA (1024-bit)** for key exchange and **AES-CBC (256-bit)** for data encryption.
   - AES encryption is implemented with **zero IV** and **PKCS#7 padding**.

2. **📊 SQLite Database**
   - The server maintains an SQLite database (`defensive.db`) with two tables:
     - **clients**: Stores client IDs, names, public keys, AES keys, and last seen timestamps.
     - **files**: Stores metadata about received files, including the file name, path, and verification status.

3. **🛡️ File Integrity Verification**
   - **CRC32** checksum is used to verify file integrity after transmission. The client and server exchange this checksum to ensure the file has not been altered during transfer.

4. **⚠️ Error Handling and Reconnection**
   - The server and client are equipped with detailed logging to handle errors.
   - 🔄 Reconnection requests (code `827`) are managed to ensure the client can recover from interruptions.

### ⚙️ Usage Instructions

1. **🖧 Server Setup**
   - Run `server_sql.py` to start the server. The server reads the port number from `port.info` and initializes the database (`defensive.db`) if not already present.
   - The server listens for connections, manages client registration, and stores received files in the `received_files` directory.

2. **🖥️ Client Setup**
   - Compile `client.cpp` using **Visual Studio 2022** with **C++17**.
   - Prepare the `transfer.info` file with the following content:
     ```
     <Server IP>:<Port Number>
     <Client Name>
     <File Path>
     ```
   - Execute the compiled client executable. The client will initiate communication with the server, handle encryption, and securely transfer the specified file. 📂

### 🔢 Protocol Codes

The following codes are used to manage communication between the client and server:

- **825**: Client registration 📝
- **826**: Sending public key 🔑
- **827**: Reconnection 🔄
- **828**: Sending encrypted file 📤
- **900-902**: File CRC verification ✅

Server response codes:
- **1600-1607**: Various server responses indicating success, failure, or errors ⚠️.

---

### 📝 Technical Notes

- **Error Handling**: The client and server handle errors such as invalid payloads, failed decryption, and database issues by sending appropriate response codes.
- **Multi-user Support**: The server supports multiple clients by spawning new threads for each client connection. 🧵
- **Security Practices**: Defensive programming techniques are applied throughout the implementation to prevent common vulnerabilities such as unchecked inputs and unsafe memory operations.

### 🙏 Acknowledgements

This project was developed as part of the **Defensive Systems Programming** course at **OUI**. Special thanks to the **Open University of Israel** for providing the foundation and resources for this learning experience. 🎓✨

Thank you for checking out my project! 😊 Feel free to reach out if you have any questions or suggestions. 🚀💬
