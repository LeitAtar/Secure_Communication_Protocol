# 🛡️ Defensive Systems Programming Final Project - OUI

Hey there! 👋 Welcome to my final project for the **Defensive Systems Programming** course at the **Open University of Israel (OUI)**. This journey is all about building a secure client-server application for encrypted file transfer. We'll dive into defensive coding practices using both C++ (for the client) and Python (for the server). Ready to explore? Let's get started! 🚀

---

## 🔍 What's the Big Idea?

Imagine sending files securely over the internet without a single worry. That's what we're crafting here—a secure file transfer protocol between a C++ client and a Python server. The server manages users, handles encryption keys, and receives files with grace and security. Key features? **Encrypted communication** 🔒, **file integrity verification** ✅, and **multi-user support** 👥.

- **Client Language**: C++ 🖥️
- **Server Language**: Python 3.12.1 🐍
- **Encryption Libraries**: Crypto++ (C++), PyCryptodome (Python)

---

## 🏗️ How It All Comes Together

### 1. The Client Side (C++17)

- **Batch Mode Operation**: The client runs in batch mode, reading server info from a `transfer.info` file. No GUI to distract us here!
- **Crypto++ Library**: We're using this nifty library for all our encryption magic tricks.
- **RSA Key Exchange**: The client generates an RSA key pair and sends the public key to the server. 🔑 Abracadabra!
- **AES Encryption**: The server sends back an encrypted AES key, which the client uses to encrypt the file. 🔒 Voila!
- **CRC32 Verification**: After sending the file, the client calculates a CRC32 checksum to ensure everything arrived safe and sound. ✅

### 2. The Server Side (Python 3.12.1)

- **Concurrent Client Handling**: Thanks to Python's `threading` module, the server can juggle multiple clients at once. 🧵 Multitasking FTW!
- **SQLite Database**: All client info and files are stored in `defensive.db`, keeping our data snug and secure. 📂
- **AES Key Management**: The server generates and securely stores an AES key for each client. No key left behind! 🔑

---

## 📁 What's Inside the Project?

- **`client.cpp`**: The main C++ client application handling everything from registration to secure file transfer. It's like the Swiss Army knife of clients!
- **`client.h`**: Header file defining constants, functions, and protocol codes. Think of it as the client's secret recipe book.
- **`server_sql.py`**: The Python server script managing clients, file uploads, and database interactions. The server's command center!

---

## 🌟 Standout Features

### 1. 🔐 Secure Communication

- **RSA (1024-bit)**: Used for the initial key exchange. Because who doesn't love a good handshake?
- **AES-CBC (256-bit)**: Employed for encrypting files, with zero IV and PKCS#7 padding. Keeping it tight and secure!

### 2. 📊 Reliable Database Storage

- **SQLite Database (`defensive.db`)**: Contains two tables:
  - **clients**: Stores client IDs, names, public keys, AES keys, and timestamps. A who's who of our users!
  - **files**: Records metadata about received files, including names, paths, and verification status. File paparazzi!

### 3. 🛡️ File Integrity Checks

- **CRC32 Checksum**: Ensures the file hasn't been tampered with during transmission. Trust but verify!

### 4. ⚠️ Robust Error Handling & Reconnection

- **Detailed Logging**: Both client and server log activities to handle errors effectively. No mystery errors here!
- **Reconnection Support**: Clients can reconnect smoothly using code `827`. Like a boomerang!

---

## ⚙️ Getting Started

### 1. Server Setup 🖧

- **Run the Server**: Fire up `server_sql.py` to get the party started.
- **Configuration**: The server reads the port number from `port.info`. Customizable to your liking!
- **Database Initialization**: If `defensive.db` isn't around, the server creates it on the fly. Magic!
- **Operation**: The server listens for client connections, handles registrations, and stores files in the `received_files` directory. Always ready to receive!

### 2. Client Setup 🖥️

- **Compile the Client**: Use **Visual Studio 2022** with **C++17** to compile `client.cpp`. Time to get those gears turning!
- **Prepare `transfer.info`**: Include the following details:
It's like sending a letter with all the right addresses!
- **Run the Client**: Execute the compiled client. It will connect to the server, handle encryption, and transfer the specified file. Smooth as butter! 📂

---

## 🔢 Communication Protocol Codes

**Client Requests:**

- **825**: Client Registration 📝 "Hello, it's me!"
- **826**: Sending Public Key 🔑 "Here's my key!"
- **827**: Reconnection Request 🔄 "I'm back!"
- **828**: Sending Encrypted File 📤 "Incoming file!"
- **900-902**: File CRC Verification ✅ "Did you get that?"

**Server Responses:**

- **1600**: Registration Successful 🎉 "Welcome aboard!"
- **1601**: Public Key Received 👍 "Got your key!"
- **1602**: AES Key Sent 🔑 "Here's your AES key!"
- **1603**: File Received 📥 "File received loud and clear!"
- **1604**: CRC Verification Passed ✅ "All good on our end!"
- **1605**: CRC Verification Failed ❌ "Uh-oh, something's off!"
- **1606**: Error Occurred ⚠️ "We hit a snag!"
- **1607**: Reconnection Successful 🔄 "Good to have you back!"

---

## 📝 Technical Highlights

- **Defensive Programming**: Careful validation and error checking are implemented to prevent vulnerabilities. Safety first!
- **Multi-threading**: The server uses threading to handle multiple clients without breaking a sweat. 🧵 Keeping all the plates spinning!
- **Error Handling**: From invalid payloads to decryption failures, the system handles errors gracefully. No drama here!

---

## 🙏 Acknowledgments

A huge thank you to the **Open University of Israel** for providing the resources and guidance throughout this course. This project was both challenging and rewarding, and I appreciate the support from instructors and peers alike. Couldn't have done it without you! 🎓✨

---

Thanks for stopping by! 😊 If you have any questions or feedback, don't hesitate to reach out. Let's keep making the digital world a safer place, one line of code at a time! 🚀💬
