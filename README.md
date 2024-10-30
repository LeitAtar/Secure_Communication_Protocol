# 🛡️ Secure File Transfer Magic 🎩✨

Welcome to the **Defensive Systems Programming Final Project** for the **Open University of Israel (OUI)**! 🎓 This project is a whimsical journey into the realms of secure file transfer between a C++ client and a Python server. We're blending cryptography 🕵️‍♂️, network programming 🌐, and a sprinkle of defensive coding 🛡️ to create a robust and secure application. Ready to embark on this adventure? Let's dive in! 🚀

---

## 📚 Table of Contents

- [🌟 What's the Buzz? 🐝](#-whats-the-buzz-)
- [🧩 How Does the Magic Happen? 🪄](#-how-does-the-magic-happen-)
  - [🖥️ The Client Side (C++17)](#-the-client-side-c17)
  - [🐍 The Server Side (Python 3.12.1)](#-the-server-side-python-3121)
- [📁 What's Inside the Spellbook? 📜](#-whats-inside-the-spellbook-)
- [🚀 Features That Make Us Soar](#-features-that-make-us-soar)
  - [🔐 Secure Communication](#-secure-communication)
  - [📊 Reliable Database Storage](#-reliable-database-storage)
  - [🛡️ File Integrity Checks](#-file-integrity-checks)
  - [⚙️ Robust Error Handling & Reconnection](#-robust-error-handling--reconnection)
- [🎮 Let's Get Started! 🎉](#-lets-get-started-)
  - [🖧 Server Setup](#-server-setup)
  - [🖥️ Client Setup](#-client-setup)
- [🔄 Communication Protocol Codes](#-communication-protocol-codes)
- [🛠️ Technical Marvels](#-technical-marvels)
- [🤝 Joining the Quest](#-joining-the-quest)
- [🙏 Acknowledgments](#-acknowledgments)
- [📞 Reach Out!](#-reach-out)

---

## 🌟 What's the Buzz? 🐝

Imagine sending your precious files over the internet without a care in the world, knowing they're wrapped up tighter than a mummy in a tomb. 🧟‍♂️ That's exactly what we're creating here! A secure client-server application that ensures your files are transferred safely, securely, and with a touch of magic. ✨

**Key Features:**

- **🔒 Encrypted Communication**: Keep those prying eyes away!
- **✅ File Integrity Verification**: Trust, but verify.
- **👥 Multi-User Support**: The more, the merrier!

---

## 🧩 How Does the Magic Happen? 🪄

### 🖥️ The Client Side (C++17)

- **Batch Mode Operation**: No pesky GUIs here! The client reads server info from a `transfer.info` file. Simple and efficient. 📄
- **Crypto++ Library**: Our trusty wand for all encryption spells. 🧙‍♂️
- **🔑 RSA Key Exchange**: The client conjures an RSA key pair and shares the public key with the server.
- **🔐 AES Encryption**: The server sends back an enchanted AES key, which the client uses to encrypt the file.
- **🧪 CRC32 Verification**: A potion to ensure the file's integrity after the journey.

### 🐍 The Server Side (Python 3.12.1)

- **🧵 Multithreading Magic**: The server juggles multiple clients effortlessly using Python's threading. 🤹‍♂️
- **📚 SQLite Database**: A grimoire storing all client info and files securely.
- **🔑 AES Key Management**: Generating and safeguarding AES keys like a dragon guarding its treasure. 🐲

---

## 📁 What's Inside the Spellbook? 📜

- **`client.cpp`**: The valiant knight handling everything from registration to secure file transfer.
- **`client.h`**: The knight's code of honor—constants, functions, and protocol codes.
- **`server_sql.py`**: The wise old wizard managing clients, file storage, and the mystical database.

---

## 🚀 Features That Make Us Soar

### 🔐 Secure Communication

- **RSA (1024-bit)**: Our initial handshake, ensuring only the right parties communicate. 🤝
- **AES-CBC (256-bit)**: Encrypting files with the strength of a thousand suns. ☀️
  - Zero IV and PKCS#7 padding for that extra touch of security.

### 📊 Reliable Database Storage

- **SQLite Database (`defensive.db`)**:
  - **clients** table: A registry of all heroes (clients) in our realm.
  - **files** table: Chronicles of all the files received, their integrity, and their origins.

### 🛡️ File Integrity Checks

- **CRC32 Checksum**: The magical seal ensuring the file hasn't been tampered with by dark forces. 🧿

### ⚙️ Robust Error Handling & Reconnection

- **Detailed Logging**: Keeping a vigilant eye on all activities. No sneaky goblins slipping through! 👀
- **Reconnection Support**: If a client falls off their horse, they can get right back on! 🐎

---

## 🎮 Let's Get Started! 🎉

### 🖧 Server Setup

1. **Fire Up the Server**: Run `server_sql.py` and watch the magic begin. ✨
2. **Port Configuration**: The server reads the port number from `port.info`. Customize it to your liking! 🔧
3. **Database Initialization**: If `defensive.db` isn't found, the server conjures it up automatically. 🧙‍♀️
4. **Operation**: The server listens for clients, handles registrations, and stores files in the `received_files` directory.

### 🖥️ Client Setup

1. **Compile the Client**: Use **Visual Studio 2022** with **C++17** to compile `client.cpp`. Let the code knights assemble! ⚔️
2. **Prepare `transfer.info`**: Include the following magical incantations:

   ```
   <server_ip>:<port>
   <client_name>
   <file_path>
   ```

   **Example:**

   ```
   192.168.1.100:1234
   MerlinTheWizard
   C:\path\to\your\enchanted_document.txt
   ```

3. **Run the Client**: Execute the compiled client to send your file through the enchanted network. 🌐

---

## 🔄 Communication Protocol Codes

**Client Requests:**

- **825**: Client Registration 📝 "Greetings! I'd like to join the quest."
- **826**: Sending Public Key 🔑 "Here's my magic key!"
- **827**: Reconnection Request 🔄 "I'm back from the shadows!"
- **828**: Sending Encrypted File 📤 "Delivering the secret scroll!"
- **900**: File CRC Verification Passed ✅ "The scroll arrived intact!"
- **901**: File CRC Verification Failed - Retry 🔄 "Something went awry. Let's try again!"
- **902**: File CRC Verification Failed - Final ❌ "Alas, the mission failed."

**Server Responses:**

- **1600**: Registration Successful 🎉 "Welcome to the fellowship!"
- **1601**: Registration Failure 🚫 "You shall not pass!"
- **1602**: Public Key Acknowledged 👍 "Key received and accepted."
- **1603**: File Received 📥 "Scroll secured in the archives."
- **1604**: Acknowledgment Received ✅ "Message received loud and clear."
- **1605**: Reconnection Successful 🔄 "Welcome back, brave one!"
- **1606**: Reconnection Failure 🚫 "We don't recognize you."
- **1607**: General Error ⚠️ "Something's not right in the realm."

---

## 🛠️ Technical Marvels

- **Defensive Programming**: Our code is armored against the dark arts of bugs and vulnerabilities. 🛡️
- **Multi-threading**: The server handles multiple clients like a maestro conducting an orchestra. 🎶
- **Error Handling**: Gracefully recovering from mishaps, ensuring the quest continues. 🌈

---

## 🤝 Joining the Quest

Feel free to fork this repository, open issues, or submit pull requests. Let's band together to make this project legendary! 🛡️⚔️

---

## 🙏 Acknowledgments

A heartfelt thank you to the **Open University of Israel** for guiding us through this magical journey. The wisdom imparted by the instructors and the camaraderie among peers made this quest unforgettable. Thank you! 🌟

---

## 📞 Reach Out!

Got questions, ideas, or just want to chat about magic and code? Don't hesitate to reach out! Let's weave spells together to make the digital realm a safer place. 🌐✨

---

Thanks for stopping by! May your code be bug-free and your quests successful! Happy coding! 😄👩‍💻👨‍💻
