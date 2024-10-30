// made by Dean Gabbai, ID 326256112
// version-025
// client.h

#ifndef CLIENT_H
#define CLIENT_H
//------------ include section ------------
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <stdexcept>
#include <algorithm>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/secblock.h>
#include <cryptopp/crc.h>
#include <cryptopp/base64.h>
#include <cryptopp/queue.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "ws2_32.lib")


namespace fs = std::filesystem;

//------------ constants section -_- ------------ 

constexpr uint8_t CLIENT_VERSION = 3;
constexpr size_t CLIENT_ID_SIZE = 16;
constexpr size_t NAME_SIZE = 255;
constexpr size_t PUBLIC_KEY_SIZE = 160; // X.509 DER format for 1024-bit RSA key
constexpr size_t AES_KEY_SIZE = 32;     // 256-bit AES key
constexpr size_t CRC_SIZE = 4;
constexpr int MAX_RETRIES = 3;

// ------------ protocol codes section ------------
constexpr uint16_t CODE_REGISTER = 825;
constexpr uint16_t CODE_SEND_PUBLIC_KEY = 826;
constexpr uint16_t CODE_RECONNECT = 827;
constexpr uint16_t CODE_SEND_FILE = 828;
constexpr uint16_t CODE_CRC_VALID = 900;
constexpr uint16_t CODE_CRC_INVALID_RETRY = 901;
constexpr uint16_t CODE_CRC_INVALID_FINAL = 902;

constexpr uint16_t RESPONSE_REGISTRATION_SUCCESS = 1600;
constexpr uint16_t RESPONSE_REGISTRATION_FAILURE = 1601;
constexpr uint16_t RESPONSE_PUBLIC_KEY_ACK = 1602;
constexpr uint16_t RESPONSE_FILE_RECEIVED = 1603;
constexpr uint16_t RESPONSE_ACKNOWLEDGEMENT = 1604;
constexpr uint16_t RESPONSE_RECONNECT_SUCCESS = 1605;
constexpr uint16_t RESPONSE_RECONNECT_FAILURE = 1606;
constexpr uint16_t RESPONSE_GENERAL_ERROR = 1607;

//------------ helper functions section------------ 

// function to log messages to the console
void logMessage(const std::string& message);

// Function to display fatal errors and exit
[[noreturn]] void fatalError(const std::string& message);

// Function to read transfer information from transfer.info file
void readTransferInfo(std::string& serverIpPort, std::string& clientName,
    std::string& filePath);

// Function to check if the client is already registered
bool isRegistered();

// Function to save client information and private key
void saveClientInfo(const std::string& clientName,
    const CryptoPP::SecByteBlock& clientId,
    const CryptoPP::RSA::PrivateKey& privateKey);

// Function to load client information and private key
void loadClientInfo(std::string& clientName, CryptoPP::SecByteBlock& clientId,
    CryptoPP::RSA::PrivateKey& privateKey);

// Function to generate RSA key pair
void generateRSAKeys(CryptoPP::RSA::PrivateKey& privateKey,
    CryptoPP::RSA::PublicKey& publicKey);

// Function to send all data over the socket
void sendAll(SOCKET socket, const char* data, size_t length);

// Function to receive all data from the socket
void recvAll(SOCKET socket, char* data, size_t length);

// Function to build and send a request to the server
void sendRequest(SOCKET socket, uint16_t code,
    const CryptoPP::SecByteBlock& clientId,
    const std::vector<CryptoPP::byte>& payload);

// Function to receive a response from the server
void receiveResponse(SOCKET socket, uint8_t& version, uint16_t& code,
    std::vector<CryptoPP::byte>& payload);

// Function to encrypt data using AES-CBC with zero IV and PKCS#7 padding
void encryptAES(const CryptoPP::SecByteBlock& key, const std::vector<CryptoPP::byte>& plainText,
    std::vector<CryptoPP::byte>& cipherText);

// Function to compute CRC32 checksum compatible with cksum command
uint32_t computeCRC32(const std::vector<CryptoPP::byte>& data);

#endif // CLIENT_H
