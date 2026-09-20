#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

#include <openssl/evp.h>   
#include <openssl/pem.h>   
#include <openssl/bio.h>
#include <openssl/rand.h>

#include "../include/utils.hpp"
#include "../include/constants.hpp"

void send_all(int sd, const unsigned char* message, uint32_t len)
{
    int ret, bytes_needed;
    uint32_t len_net;

    // first, send the size of the message
    len_net = htonl(len);   // conversion in network byte order
    bytes_needed = sizeof(uint32_t);
    ret = send(sd, (void*)&len_net, bytes_needed, 0);     
    if(ret < bytes_needed)
    {
        perror("Error while sending");
        exit(1);
    }  

    // next, send the message itself
    bytes_needed = len;
    ret = send(sd, (void*)message, bytes_needed, 0);     
    if(ret < bytes_needed)
    {
        perror("Error while sending");
        exit(1);
    }
}

void recv_all(int sd, unsigned char*& message, uint32_t& len)
{
    int ret, bytes_needed;
   
    // first, receive the size of the message
    bytes_needed = sizeof(uint32_t);
    ret = recv(sd, (void*)&len, bytes_needed, 0);
    if(ret == 0)
    {
        printf("Connection closed, session ended \n");
        exit(0);
    }
    if(ret < bytes_needed)
    {
        perror("Error while receiving");
        exit(1);
    }

    len = ntohl(len);  // conversion in host byte order

    // buffer allocation for the message
    message = (unsigned char*)malloc(len);

    // next, receive the message itself
    bytes_needed = len;
    ret = recv(sd, (void*)message, bytes_needed, 0);
    if(ret == 0)
    {
        printf("Connection closed, session ended \n");
        exit(0);
    }
    if(ret < bytes_needed)
    {
        perror("Error while receiving");
        exit(1);
    }
}

void auth_encrypt(const unsigned char* plaintext, int plainlen, const unsigned char* AAD, int AAD_len, const unsigned char* key, const unsigned char* iv, unsigned char* tag, unsigned char* ciphertext, int& cipherlen)
{
    int outlen;

    // context allocation
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // encryption (initialization + update + finalization)
    EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    EVP_EncryptUpdate(ctx, NULL, &outlen, AAD, AAD_len);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, plainlen);
    cipherlen = outlen;
    EVP_EncryptFinal(ctx, ciphertext + cipherlen, &outlen);
    cipherlen += outlen;

    // retrieve the tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag);

    // context deallocation 
    EVP_CIPHER_CTX_free(ctx);
}

void auth_decrypt(const unsigned char* ciphertext, int cipherlen, const unsigned char* AAD, int AAD_len, const unsigned char* key, const unsigned char* iv, unsigned char* tag, unsigned char* plaintext, int& plainlen)
{
    int outlen, res;

    // decryption context initialization
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // decryption (initialization + update + finalization)
    EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    EVP_DecryptUpdate(ctx, NULL, &outlen, AAD, AAD_len);
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, cipherlen);
    plainlen = outlen;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, tag);
    res = EVP_DecryptFinal(ctx, plaintext + plainlen, &outlen);
    if(res == 0)
    {
        printf("Error while decrypting: tag mismatch \n");
        exit(1);
    }
    plainlen += outlen;

    // context deallocation 
    EVP_CIPHER_CTX_free(ctx);
}

void compose_std_message(const unsigned char* plaintext, int plainlen, const unsigned char* nonce, const unsigned char* key, std::vector<unsigned char>& message)
{
    // buffer allocation for the ciphertext
    unsigned char* ciphertext = (unsigned char*)malloc(plainlen);

    // buffer allocation for the tag
    unsigned char tag[TAG_SIZE];

    // buffer allocation for the IV
    unsigned char iv[IV_SIZE];

    // generate the IV
    RAND_bytes(iv, IV_SIZE);

    // conversion in network byte order
    uint32_t cipherlen_net = htonl(plainlen); 

    // construct the AAD fragment (we can use the plaintext length instead of the ciphertext lenght since AES in GCM mode does not add padding)
    std::vector<unsigned char> AAD;
    AAD.insert(AAD.end(), (unsigned char*)&cipherlen_net, (unsigned char*)&cipherlen_net + sizeof(uint32_t));
    AAD.insert(AAD.end(), nonce, nonce + NONCE_SIZE);

    // encryption
    int cipherlen;
    auth_encrypt(plaintext, plainlen, AAD.data(), AAD.size(), key, iv, tag, ciphertext, cipherlen);

    // construct the message to be sent: [iv || cipherlen || ciphertext || nonce || tag]
    message.insert(message.end(), iv, iv + IV_SIZE);
    message.insert(message.end(), (unsigned char*)&cipherlen_net, (unsigned char*)&cipherlen_net + sizeof(uint32_t));
    message.insert(message.end(), ciphertext, ciphertext + cipherlen);
    message.insert(message.end(), nonce, nonce + NONCE_SIZE);
    message.insert(message.end(), tag, tag + TAG_SIZE);

    // free resources
    free(ciphertext);
}

void parse_std_message(const unsigned char* message, const unsigned char* key, unsigned char*& plaintext, unsigned char* nonce)
{
    int offset;
    uint32_t cipherlen_net, cipherlen;

    // buffer allocation for the tag
    unsigned char tag[TAG_SIZE];

    // buffer allocation for the IV
    unsigned char iv[IV_SIZE];

    // read the IV
    memcpy(iv, message, IV_SIZE);
    offset = IV_SIZE;

    // read the length of the ciphertext
    memcpy(&cipherlen_net, message + offset, sizeof(uint32_t));
    cipherlen = ntohl(cipherlen_net);   // conversion in host byte order
    offset += sizeof(uint32_t);

    // read the ciphertext itself
    unsigned char* ciphertext = (unsigned char*)malloc(cipherlen);
    memcpy(ciphertext, message + offset, cipherlen);
    offset += cipherlen;

    // read the nonce 
    memcpy(nonce, message + offset, NONCE_SIZE);
    offset += NONCE_SIZE;

    // read the tag
    memcpy(tag, message + offset, TAG_SIZE);

    // decrypt and verify and the integrity of the message:
    // buffer allocation for the decrypted text
    plaintext = (unsigned char*)malloc(cipherlen);

    // construct the AAD fragment
    std::vector<unsigned char> AAD;
    AAD.insert(AAD.end(), (unsigned char*)&cipherlen_net, (unsigned char*)&cipherlen_net + sizeof(uint32_t));
    AAD.insert(AAD.end(), nonce, nonce + NONCE_SIZE);

    // decryption
    int plainlen;
    auth_decrypt(ciphertext, cipherlen, AAD.data(), AAD.size(), key, iv, tag, plaintext, plainlen);

    // free resources
    free(ciphertext);
}
