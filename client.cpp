// made by Dean Gabbai, ID 326256112
// version-025
// client.cpp
// Have Fun checking this code, as I've had making it :)

#include "client.h"

namespace fs = std::filesystem;

// Helper functions section here

// Function to log messages to the console
void logMessage(const std::string& message) {
    std::cout << message << std::endl;
}

// Function to display fatal errors and exit
[[noreturn]] void fatalError(const std::string& message) {
    std::cerr << "Fatal error: " << message << std::endl;
    std::cout << "Fatal error: " << message << std::endl; // Also write to stdout
    exit(EXIT_FAILURE);
}

// Function to read transfer information from transfer.info file
void readTransferInfo(std::string& serverIpPort, std::string& clientName,
    std::string& filePath) {
    std::ifstream transferFile("transfer.info");
    if (!transferFile) {
        fatalError("Error opening transfer.info");
    }

    std::getline(transferFile, serverIpPort);
    std::getline(transferFile, clientName);
    std::getline(transferFile, filePath);

    transferFile.close();
}

// Function to check if the client is already registered
bool isRegistered() {
    return fs::exists("me.info") && fs::exists("key.priv");
}

// Function to save client information and private key
void saveClientInfo(const std::string& clientName,
    const CryptoPP::SecByteBlock& clientId,
    const CryptoPP::RSA::PrivateKey& privateKey) {
    // Save client name and ID to me.info
    std::ofstream meFile("me.info");
    if (!meFile) {
        fatalError("Error writing to me.info");
    }

    // Write client name
    meFile << clientName << std::endl;

    // Convert clientId to hex string
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < clientId.size(); ++i) {
        ss << std::setw(2) << static_cast<int>(clientId[i]);
    }
    meFile << ss.str() << std::endl;

    // Save private key in Base64-encoded DER format
    CryptoPP::ByteQueue queue;
    privateKey.DEREncodePrivateKey(queue);
    std::string privKeyStr;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(privKeyStr), false);
    queue.CopyTo(encoder);
    encoder.MessageEnd();

    // Write private key to me.info
    meFile << privKeyStr << std::endl;

    meFile.close();

    // Save private key to key.priv in binary format
    CryptoPP::FileSink file("key.priv");
    privateKey.DEREncodePrivateKey(file);
}

// Function to load client information and private key
void loadClientInfo(std::string& clientName, CryptoPP::SecByteBlock& clientId,
    CryptoPP::RSA::PrivateKey& privateKey) {
    // Load client name and ID from me.info
    std::ifstream meFile("me.info");
    if (!meFile) {
        fatalError("Error opening me.info");
    }

    // Read client name
    std::getline(meFile, clientName);

    // Read client ID as hex string
    std::string clientIdHex;
    std::getline(meFile, clientIdHex);

    // Read private key (Base64 encoded)
    std::string encodedPrivKey;
    std::string line;
    while (std::getline(meFile, line)) {
        encodedPrivKey += line + "\n";
    }
    meFile.close();

    // Convert hex string to binary
    clientId.resize(CLIENT_ID_SIZE);
    for (size_t i = 0; i < CLIENT_ID_SIZE; ++i) {
        std::string byteString = clientIdHex.substr(2 * i, 2);
        clientId[i] = static_cast<CryptoPP::byte>(
            std::stoul(byteString, nullptr, 16));
    }

    // Decode and load private key from me.info
    CryptoPP::ByteQueue queue;
    CryptoPP::Base64Decoder decoder;
    decoder.Attach(new CryptoPP::Redirector(queue));
    CryptoPP::StringSource ss(encodedPrivKey, true, new CryptoPP::Redirector(decoder));

    privateKey.BERDecodePrivateKey(queue, false, queue.MaxRetrievable());
}

// Function to generate RSA key pair
void generateRSAKeys(CryptoPP::RSA::PrivateKey& privateKey,
    CryptoPP::RSA::PublicKey& publicKey) {
    CryptoPP::AutoSeededRandomPool rng;
    privateKey.GenerateRandomWithKeySize(rng, 1024);
    publicKey.AssignFrom(privateKey);
}

// Function to send all data over the socket
void sendAll(SOCKET socket, const char* data, size_t length) {
    size_t totalSent = 0;
    while (totalSent < length) {
        int sent = send(socket, data + totalSent, static_cast<int>(length - totalSent), 0);
        if (sent == SOCKET_ERROR) {
            throw std::runtime_error("Socket send failed");
        }
        totalSent += sent;
    }
}

// Function to receive all data from the socket
void recvAll(SOCKET socket, char* data, size_t length) {
    size_t totalReceived = 0;
    while (totalReceived < length) {
        int received = recv(socket, data + totalReceived, static_cast<int>(length - totalReceived), 0);
        if (received <= 0) {
            throw std::runtime_error("Socket receive failed");
        }
        totalReceived += received;
    }
}

// Function to build and send a request to the server
void sendRequest(SOCKET socket, uint16_t code,
    const CryptoPP::SecByteBlock& clientId,
    const std::vector<CryptoPP::byte>& payload) {
    // Build the header
    std::array<CryptoPP::byte, 23> header{}; // Zero-initialized

    // Client ID
    std::copy(clientId.begin(), clientId.end(), header.begin());

    // Version
    header[16] = CLIENT_VERSION;

    // Code (assuming little-endian)
    std::memcpy(&header[17], &code, sizeof(code));

    // Payload size (assuming little-endian)
    uint32_t payloadSize = static_cast<uint32_t>(payload.size());
    std::memcpy(&header[19], &payloadSize, sizeof(payloadSize));

    // Send header
    sendAll(socket, reinterpret_cast<const char*>(header.data()), header.size());

    // Send payload if any
    if (!payload.empty()) {
        sendAll(socket, reinterpret_cast<const char*>(payload.data()), payload.size());
    }

    // Print the protocol code being sent
    logMessage("Sent request with code: " + std::to_string(code));
}

// Function to receive a response from the server
void receiveResponse(SOCKET socket, uint8_t& version, uint16_t& code,
    std::vector<CryptoPP::byte>& payload) {
    // Receive header
    std::array<CryptoPP::byte, 7> header{};
    recvAll(socket, reinterpret_cast<char*>(header.data()), header.size());

    version = header[0];

    // Code
    std::memcpy(&code, &header[1], sizeof(code));

    // Payload size
    uint32_t payloadSize = 0;
    std::memcpy(&payloadSize, &header[3], sizeof(payloadSize));

    // Receive payload
    payload.resize(payloadSize);
    if (payloadSize > 0) {
        recvAll(socket, reinterpret_cast<char*>(payload.data()), payloadSize);
    }

    // Print the protocol code received
    logMessage("Received response with code: " + std::to_string(code));
}

// Function to encrypt data using AES-CBC with zero IV and PKCS#7 padding
void encryptAES(const CryptoPP::SecByteBlock& key, const std::vector<CryptoPP::byte>& plainText,
    std::vector<CryptoPP::byte>& cipherText) {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 }; // IV filled with zeros
    encryption.SetKeyWithIV(key, key.size(), iv);

    CryptoPP::StringSource ss(plainText.data(), plainText.size(), true,
        new CryptoPP::StreamTransformationFilter(encryption,
            new CryptoPP::VectorSink(cipherText)
            // Using default padding (PKCS#7)
        )
    );
}

// Function to compute CRC32 checksum compatible with cksum command
uint32_t computeCRC32(const std::vector<CryptoPP::byte>& data) {
    CryptoPP::CRC32 crc;
    crc.Update(data.data(), data.size());
    uint32_t checksum;
    crc.TruncatedFinal(reinterpret_cast<CryptoPP::byte*>(&checksum), sizeof(checksum));
    return checksum;
}

int main() {
    std::cout << "version-023" << std::endl;
    try {
        logMessage("Starting client program.");

        // Initialize Winsock
        logMessage("Initializing Winsock...");
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            fatalError("WSAStartup failed");
        }
        logMessage("Winsock initialized successfully.");

        // Read transfer.info
        logMessage("Reading transfer.info...");
        std::string serverIpPort, clientName, filePath;
        readTransferInfo(serverIpPort, clientName, filePath);
        logMessage("Server IP and port: " + serverIpPort);
        logMessage("Client name: " + clientName);
        logMessage("File path: " + filePath);

        // Extract IP and port
        logMessage("Extracting server IP and port...");
        size_t colonPos = serverIpPort.find(':');
        if (colonPos == std::string::npos) {
            fatalError("Invalid server IP and port format");
        }
        std::string serverIp = serverIpPort.substr(0, colonPos);
        uint16_t serverPort = static_cast<uint16_t>(std::stoul(serverIpPort.substr(colonPos + 1)));
        logMessage("Server IP: " + serverIp);
        logMessage("Server port: " + std::to_string(serverPort));

        // Setup socket
        logMessage("Creating socket...");
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            fatalError("Socket creation failed");
        }
        logMessage("Socket created successfully.");

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr);
        serverAddr.sin_port = htons(serverPort);

        // Connect to server
        logMessage("Connecting to server...");
        if (connect(sock, reinterpret_cast<sockaddr*>(&serverAddr),
            sizeof(serverAddr)) == SOCKET_ERROR) {
            fatalError("Connection to server failed");
        }
        logMessage("Connected to server successfully.");

        // Variables
        logMessage("Initializing variables...");
        CryptoPP::SecByteBlock clientId(CLIENT_ID_SIZE);
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::RSA::PublicKey publicKey;
        CryptoPP::SecByteBlock aesKey; // Do not initialize size here
        bool registered = isRegistered();
        int attempt = 0;
        bool needToReconnect = false;
        uint16_t requestCode = 0; // Declare requestCode once here

        if (registered) {
            logMessage("Client is already registered.");
        }
        else {
            logMessage("Client is not registered.");
        }

        do {
            needToReconnect = false;
            logMessage("Starting registration/reconnection loop...");

            if (!registered) {
                logMessage("Beginning registration process...");
                // Registration
                clientId.Assign(CryptoPP::SecByteBlock(CLIENT_ID_SIZE)); // Zero-initialized

                // Build payload for registration (code 825)
                requestCode = CODE_REGISTER; // Assign value instead of redeclaring

                std::vector<CryptoPP::byte> payload(NAME_SIZE, 0);
                std::copy(clientName.begin(), clientName.end(), payload.begin());

                // Send registration request
                for (attempt = 0; attempt < MAX_RETRIES; ++attempt) {
                    logMessage("Attempt " + std::to_string(attempt + 1) + " to register...");
                    sendRequest(sock, requestCode, clientId, payload);

                    // Receive response
                    uint8_t serverVersion;
                    uint16_t responseCode;
                    std::vector<CryptoPP::byte> responsePayload;
                    receiveResponse(sock, serverVersion, responseCode, responsePayload);

                    if (responseCode == RESPONSE_REGISTRATION_SUCCESS) {
                        // Registration succeeded
                        logMessage("Registration successful.");

                        if (responsePayload.size() != CLIENT_ID_SIZE) {
                            fatalError("Invalid client ID size in response");
                        }
                        clientId.Assign(responsePayload.data(), CLIENT_ID_SIZE);

                        // Generate RSA keys
                        logMessage("Generating RSA key pair...");
                        generateRSAKeys(privateKey, publicKey);
                        logMessage("RSA key pair generated.");

                        // Save client info and private key
                        logMessage("Saving client information and private key...");
                        saveClientInfo(clientName, clientId, privateKey);
                        logMessage("Client information and private key saved.");

                        registered = true;

                        logMessage("Proceeding to public key exchange...");
                        break;
                    }
                    else {
                        logMessage("Server responded with an error during registration.");
                    }
                }
                if (attempt == MAX_RETRIES) {
                    fatalError("Failed to register after multiple attempts");
                }

                // Send public key to server (code 826)
                requestCode = CODE_SEND_PUBLIC_KEY; // Assign value instead of redeclaring

                // Build payload
                std::vector<CryptoPP::byte> pubKeyPayload(NAME_SIZE + PUBLIC_KEY_SIZE, 0);

                // Name
                std::copy(clientName.begin(), clientName.end(), pubKeyPayload.begin());

                // Public Key in X.509 DER format
                CryptoPP::ByteQueue queue;
                publicKey.DEREncode(queue);
                size_t keySize = queue.CurrentSize();

                if (keySize != PUBLIC_KEY_SIZE) {
                    fatalError("Public key size mismatch");
                }

                queue.Get(&pubKeyPayload[NAME_SIZE], PUBLIC_KEY_SIZE);

                // Send public key
                for (attempt = 0; attempt < MAX_RETRIES; ++attempt) {
                    logMessage("Attempt " + std::to_string(attempt + 1) + " to send public key...");
                    sendRequest(sock, requestCode, clientId, pubKeyPayload);

                    // Receive response
                    uint8_t serverVersion;
                    uint16_t responseCode;
                    std::vector<CryptoPP::byte> responsePayload;
                    receiveResponse(sock, serverVersion, responseCode, responsePayload);

                    if (responseCode == RESPONSE_PUBLIC_KEY_ACK) {
                        // Received encrypted AES key
                        logMessage("Public key acknowledged by server.");

                        if (responsePayload.size() < CLIENT_ID_SIZE) {
                            fatalError("Invalid response payload size");
                        }
                        // Extract client ID
                        if (!std::equal(clientId.begin(), clientId.end(), responsePayload.begin())) {
                            fatalError("Client ID mismatch");
                        }
                        // Encrypted AES key
                        std::vector<CryptoPP::byte> encryptedAESKey(responsePayload.size() - CLIENT_ID_SIZE);
                        std::copy(responsePayload.begin() + CLIENT_ID_SIZE, responsePayload.end(), encryptedAESKey.begin());

                        // Decrypt AES key
                        logMessage("Decrypting AES key...");
                        CryptoPP::AutoSeededRandomPool rng;
                        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

                        CryptoPP::SecByteBlock decryptedAESKey(decryptor.MaxPlaintextLength(encryptedAESKey.size()));
                        CryptoPP::DecodingResult result = decryptor.Decrypt(rng, encryptedAESKey.data(), encryptedAESKey.size(), decryptedAESKey);

                        if (!result.isValidCoding) {
                            fatalError("RSA decryption failed");
                        }

                        aesKey.Assign(decryptedAESKey.data(), result.messageLength);
                        logMessage("AES key decrypted successfully. Size: " + std::to_string(aesKey.size()));

                        // Proceed to file transfer
                        logMessage("Proceeding to file transfer...");

                        // Exit the loop
                        logMessage("Exited registration/reconnection loop.");
                        break;
                    }
                    else {
                        logMessage("Server responded with an error during public key exchange.");
                    }
                }
                if (attempt == MAX_RETRIES) {
                    fatalError("Failed to exchange keys after multiple attempts");
                }

                // Break out of the do...while loop
                break;
            }
            else {
                logMessage("Beginning reconnection process...");
                // Reconnection
                // Load client info and private key
                logMessage("Loading client information and private key...");
                loadClientInfo(clientName, clientId, privateKey);
                logMessage("Client information and private key loaded.");

                publicKey.AssignFrom(privateKey);

                // Send reconnection request (code 827)
                requestCode = CODE_RECONNECT; // Assign value instead of redeclaring

                std::vector<CryptoPP::byte> payload(NAME_SIZE, 0);
                std::copy(clientName.begin(), clientName.end(), payload.begin());

                // Send reconnection request
                for (attempt = 0; attempt < MAX_RETRIES; ++attempt) {
                    logMessage("Attempt " + std::to_string(attempt + 1) + " to reconnect...");
                    sendRequest(sock, requestCode, clientId, payload);

                    // Receive response
                    uint8_t serverVersion;
                    uint16_t responseCode;
                    std::vector<CryptoPP::byte> responsePayload;
                    receiveResponse(sock, serverVersion, responseCode, responsePayload);

                    if (responseCode == RESPONSE_RECONNECT_SUCCESS) {
                        // Reconnection approved, receive encrypted AES key
                        logMessage("Reconnection successful.");

                        if (responsePayload.size() < CLIENT_ID_SIZE) {
                            fatalError("Invalid response payload size");
                        }
                        // Extract client ID
                        if (!std::equal(clientId.begin(), clientId.end(), responsePayload.begin())) {
                            fatalError("Client ID mismatch");
                        }
                        // Encrypted AES key
                        std::vector<CryptoPP::byte> encryptedAESKey(responsePayload.size() - CLIENT_ID_SIZE);
                        std::copy(responsePayload.begin() + CLIENT_ID_SIZE, responsePayload.end(), encryptedAESKey.begin());

                        // Decrypt AES key
                        logMessage("Decrypting AES key...");
                        CryptoPP::AutoSeededRandomPool rng;
                        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

                        CryptoPP::SecByteBlock decryptedAESKey(decryptor.MaxPlaintextLength(encryptedAESKey.size()));
                        CryptoPP::DecodingResult result = decryptor.Decrypt(rng, encryptedAESKey.data(), encryptedAESKey.size(), decryptedAESKey);

                        if (!result.isValidCoding) {
                            fatalError("RSA decryption failed");
                        }

                        aesKey.Assign(decryptedAESKey.data(), result.messageLength);
                        logMessage("AES key decrypted successfully. Size: " + std::to_string(aesKey.size()));

                        registered = true; // Add this line

                        // Proceed to file transfer
                        logMessage("Proceeding to file transfer...");
                        // Exit the loop
                        logMessage("Exited registration/reconnection loop.");
                        break;
                    }
                    else if (responseCode == RESPONSE_RECONNECT_FAILURE) {
                        // Reconnection denied, need to register again
                        logMessage("Reconnection denied by server, registering again.");
                        fs::remove("me.info");
                        fs::remove("key.priv");
                        registered = false;
                        needToReconnect = true;
                        break;
                    }
                    else {
                        logMessage("Server responded with an error during reconnection.");
                    }
                }
                if (attempt == MAX_RETRIES && !needToReconnect) {
                    fatalError("Failed to reconnect after multiple attempts");
                }

                // If reconnection was successful, break out of the loop
                if (registered && !needToReconnect) {
                    break;
                }
            }
        } while (needToReconnect);

        // Ensure that the AES key has been obtained before proceeding
        if (aesKey.size() != AES_KEY_SIZE) {
            fatalError("AES key is not initialized or has incorrect size.");
        }
        logMessage("AES key is initialized.");

        // Additional logging
        logMessage("Attempting to open file: " + filePath);

        // Encrypt the file
        std::ifstream inputFile(filePath, std::ios::binary);
        if (!inputFile) {
            fatalError("Error opening file to encrypt: " + filePath);
        }
        else {
            logMessage("Successfully opened file: " + filePath);
        }

        std::vector<CryptoPP::byte> fileData((std::istreambuf_iterator<char>(inputFile)),
            std::istreambuf_iterator<char>());
        inputFile.close();

        logMessage("Read file data, size: " + std::to_string(fileData.size()) + " bytes.");

        // Encrypt the file content
        std::vector<CryptoPP::byte> encryptedFileContent;
        encryptAES(aesKey, fileData, encryptedFileContent);
        logMessage("File encrypted successfully.");

        logMessage("Encrypted file size: " + std::to_string(encryptedFileContent.size()) + " bytes.");

        // Compute CRC32 of original file
        uint32_t crc32 = computeCRC32(fileData);
        logMessage("Computed CRC32 checksum of the original file: " + std::to_string(crc32));

        // Send file to server (code 828)
        std::string fileName = fs::path(filePath).filename().string();
        logMessage("File name: " + fileName);

        requestCode = CODE_SEND_FILE; // Assign value instead of redeclaring
        uint32_t encryptedSize = static_cast<uint32_t>(encryptedFileContent.size());
        uint32_t originalSize = static_cast<uint32_t>(fileData.size());
        uint16_t packetNumber = 1; // For simplicity, assume single packet
        uint16_t totalPackets = 1;

        logMessage("Preparing payload for file transfer...");

        size_t payloadSize = sizeof(encryptedSize) + sizeof(originalSize) +
            sizeof(packetNumber) + sizeof(totalPackets) +
            NAME_SIZE + encryptedFileContent.size();
        std::vector<CryptoPP::byte> payload(payloadSize);

        auto ptr = payload.begin();

        // Encrypted file size
        std::memcpy(&(*ptr), &encryptedSize, sizeof(encryptedSize));
        ptr += sizeof(encryptedSize);

        // Original file size
        std::memcpy(&(*ptr), &originalSize, sizeof(originalSize));
        ptr += sizeof(originalSize);

        // Packet number and total packets
        std::memcpy(&(*ptr), &packetNumber, sizeof(packetNumber));
        ptr += sizeof(packetNumber);
        std::memcpy(&(*ptr), &totalPackets, sizeof(totalPackets));
        ptr += sizeof(totalPackets);

        // File name
        std::vector<CryptoPP::byte> fileNameBuffer(NAME_SIZE, 0);
        std::copy(fileName.begin(), fileName.end(), fileNameBuffer.begin());
        std::copy(fileNameBuffer.begin(), fileNameBuffer.end(), ptr);
        ptr += NAME_SIZE;

        // Encrypted file content
        std::copy(encryptedFileContent.begin(), encryptedFileContent.end(), ptr);

        // Send file with retries
        logMessage("Preparing to send file transfer request with code: " + std::to_string(CODE_SEND_FILE));
        for (attempt = 0; attempt < MAX_RETRIES; ++attempt) {
            logMessage("Attempt " + std::to_string(attempt + 1) + " to send file...");
            sendRequest(sock, requestCode, clientId, payload);

            // Receive response
            uint8_t serverVersion;
            uint16_t responseCode;
            std::vector<CryptoPP::byte> responsePayload;
            receiveResponse(sock, serverVersion, responseCode, responsePayload);

            if (responseCode == RESPONSE_FILE_RECEIVED) {
                // File received correctly with CRC
                logMessage("Server received file and sent RESPONSE_FILE_RECEIVED.");

                size_t expectedSize = CLIENT_ID_SIZE + sizeof(encryptedSize) + NAME_SIZE + CRC_SIZE;
                logMessage("Expected response payload size: " + std::to_string(expectedSize));
                logMessage("Actual response payload size: " + std::to_string(responsePayload.size()));
                if (responsePayload.size() != expectedSize) {
                    fatalError("Invalid response payload size");
                }
                auto respPtr = responsePayload.begin();

                // Extract client ID
                if (!std::equal(clientId.begin(), clientId.end(), respPtr)) {
                    fatalError("Client ID mismatch");
                }
                respPtr += CLIENT_ID_SIZE;

                // Encrypted file size
                uint32_t serverEncryptedSize;
                std::memcpy(&serverEncryptedSize, &(*respPtr), sizeof(serverEncryptedSize));
                respPtr += sizeof(serverEncryptedSize);

                // File name
                std::vector<char> respFileName(NAME_SIZE);
                std::memcpy(respFileName.data(), &(*respPtr), NAME_SIZE);
                respPtr += NAME_SIZE;

                // CRC
                uint32_t serverCRC;
                std::memcpy(&serverCRC, &(*respPtr), CRC_SIZE);

                logMessage("Server CRC: " + std::to_string(serverCRC));

                if (crc32 == serverCRC) {
                    // CRCs match, send code 900
                    logMessage("CRC matches. Sending CODE_CRC_VALID.");
                    requestCode = CODE_CRC_VALID; // Assign value instead of redeclaring

                    std::vector<CryptoPP::byte> crcPayload(NAME_SIZE, 0);
                    std::copy(fileName.begin(), fileName.end(), crcPayload.begin());

                    sendRequest(sock, requestCode, clientId, crcPayload);

                    // Receive acknowledgment
                    receiveResponse(sock, serverVersion, responseCode, responsePayload);
                    if (responseCode == RESPONSE_ACKNOWLEDGEMENT) {
                        logMessage("File transfer successful!");
                        break;
                    }
                    else {
                        logMessage("Server responded with an error during acknowledgment.");
                    }
                }
                else {
                    // CRCs do not match, send code 901
                    logMessage("CRC mismatch. Expected: " + std::to_string(crc32) + ", Received: " + std::to_string(serverCRC));
                    requestCode = CODE_CRC_INVALID_RETRY; // Assign value instead of redeclaring

                    std::vector<CryptoPP::byte> crcPayload(NAME_SIZE, 0);
                    std::copy(fileName.begin(), fileName.end(), crcPayload.begin());
                    sendRequest(sock, requestCode, clientId, crcPayload);

                    logMessage("CRC mismatch. Retrying...");
                    continue; // Retry
                }
            }
            else {
                logMessage("Server responded with an error during file transfer.");
                continue; // Retry
            }
        }

        if (attempt == MAX_RETRIES) {
            // Send code 902
            requestCode = CODE_CRC_INVALID_FINAL; // Assign value instead of redeclaring

            std::vector<CryptoPP::byte> crcPayload(NAME_SIZE, 0);
            std::copy(fileName.begin(), fileName.end(), crcPayload.begin());
            sendRequest(sock, requestCode, clientId, crcPayload);

            logMessage("Failed to transfer file after multiple attempts.");

            // Receive acknowledgment
            uint8_t serverVersion;
            uint16_t responseCode;
            std::vector<CryptoPP::byte> responsePayload;
            receiveResponse(sock, serverVersion, responseCode, responsePayload);
            if (responseCode == RESPONSE_ACKNOWLEDGEMENT) {
                logMessage("Server acknowledged termination.");
            }
            else {
                logMessage("Server responded with an error during termination.");
            }

            logMessage("Closing socket and cleaning up.");
            closesocket(sock);
            WSACleanup();
            return EXIT_FAILURE;
        }

        // Cleanup
        logMessage("Closing socket and cleaning up.");
        closesocket(sock);
        WSACleanup();
        logMessage("Client program completed successfully.");

    }
    catch (const std::exception& e) {
        fatalError(e.what());
    }
    catch (...) {
        fatalError("An unknown error occurred.");
    }

    return EXIT_SUCCESS;
}
