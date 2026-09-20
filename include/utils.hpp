#pragma once

#include <stdlib.h> // for uint32_t
#include <vector>

// utility functions for sending and receiving both the size of the message and the message itself in one call
void send_all(int sd, const unsigned char* message, uint32_t len);
void recv_all(int sd, unsigned char*& message, uint32_t& len);

// authenticated encryption and decryption functions
void auth_encrypt(const unsigned char* plaintext, int plainlen, const unsigned char* AAD, int AAD_len, const unsigned char* key, const unsigned char* iv, unsigned char* tag, unsigned char* ciphertext, int& cipherlen);
void auth_decrypt(const unsigned char* ciphertext, int cipherlen, const unsigned char* AAD, int AAD_len, const unsigned char* key, const unsigned char* iv, unsigned char* tag, unsigned char* plaintext, int& plainlen);

// functions for composing and parsing messages using the standard protocol format
void compose_std_message(const unsigned char* plaintext, int plainlen, const unsigned char* nonce, const unsigned char* key, std::vector<unsigned char>& message);
void parse_std_message(const unsigned char* message, const unsigned char* key, unsigned char*& plaintext, unsigned char* nonce);
