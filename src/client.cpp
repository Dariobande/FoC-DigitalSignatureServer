#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <vector>

#include <openssl/evp.h>   
#include <openssl/pem.h>   
#include <openssl/bio.h>  
#include <openssl/rand.h>
#include <openssl/err.h>

#include "../include/utils.hpp"
#include "../include/constants.hpp"

// server listening port
#define SERVER_PORT 4242

// delimiter used to parse user input
#define DELIMITER " "

// function that prints the menu of commands available to users after securely connected to the server
void print_menu()
{
    printf("\n");
	for(int i = 0; i < 25; i++)
        printf("*");
   
    printf(" CLIENT STARTED ");

    for(int i = 0; i < 25; i++)
        printf("*");

    printf("\n");
	printf("Available commands: \n");
    printf("1) CreateKeys          --> create and store your key pair \n");
    printf("2) SignDoc <file>      --> sign the specified document \n");
    printf("3) GetPublicKey <user> --> get the public key of a user \n");
    printf("4) DeleteKeys          --> delete your key pair \n");
    printf("5) Stop                --> disconnect from the server \n");

    for(int i = 0; i < 66; i++)
        printf("*");
}

// handshake protocol function which returns the session key and the last nonce sent by the server (used to avoid replays of the first request sent by the client)
void handshake_protocol(int sd, unsigned char*& sym_key, unsigned char* nonce, char*& username_out)
{
    // utility variables 
    uint32_t len, cipherlen;
    int offset;

    // buffer allocations
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char nonce_c[NONCE_SIZE];
    unsigned char nonce_s[NONCE_SIZE];

    EVP_PKEY *dh_params = NULL;
    BIO *bio = NULL;

    // create BIO from a file
    bio = BIO_new_file("keys/dhparam.pem", "r");
    if(!bio) 
    {
        perror("Error opening dhparam.pem");
        exit(1);
    }

    // read DH parameters
    dh_params = PEM_read_bio_Parameters(bio, NULL);
    if(!dh_params) 
    {
        perror("Error reading DH parameters from dhparam.pem");
        exit(1);
    }

    // cleanup
    BIO_free(bio);

    // create context for key generation 
    EVP_PKEY_CTX* ctx_gen = EVP_PKEY_CTX_new(dh_params, NULL);

    // generate a new key 
    EVP_PKEY* my_prvkey = NULL;
    EVP_PKEY_keygen_init(ctx_gen);
    EVP_PKEY_keygen(ctx_gen, &my_prvkey);

    // free resources
    EVP_PKEY_CTX_free(ctx_gen);
    EVP_PKEY_free(dh_params);

    // buffer to extract the public key
    BIO* pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub_bio, my_prvkey);

    unsigned char* pubkey = nullptr; 
    long pubkey_len = BIO_get_mem_data(pub_bio, &pubkey);

    // the variable pubkey now contains the public key in PEM format and can be sent to the server (message M1)
    send_all(sd, pubkey, pubkey_len);

    // receive the server's message M2
    unsigned char* message_M2;
    recv_all(sd, message_M2, len);

    // parsing of the message received:
    // read the IV
    memcpy(iv, message_M2, IV_SIZE);
    offset = IV_SIZE;

    // read the length of the server's public key
    uint32_t server_pubkey_len_net;
    memcpy(&server_pubkey_len_net, message_M2 + offset, sizeof(uint32_t));
    uint32_t server_pubkey_len = ntohl(server_pubkey_len_net);   // conversion in host byte order
    offset += sizeof(uint32_t);

    // read the public key 
    unsigned char* server_pubkey_raw = (unsigned char*)malloc(server_pubkey_len);
    memcpy(server_pubkey_raw, message_M2 + offset, server_pubkey_len);
    offset += server_pubkey_len;

    // create a copy null-terminated
    char* pubkey_pem = (char*)malloc(server_pubkey_len + 1);
    memcpy(pubkey_pem, server_pubkey_raw, server_pubkey_len);
    pubkey_pem[server_pubkey_len] = '\0';

    // create the BIO of the copy 
    bio = BIO_new_mem_buf(pubkey_pem, -1);  

    // load the public key from the BIO into an EVP_PKEY structure
    EVP_PKEY* server_pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
   
    // free resources
    free(pubkey_pem);
    BIO_free(bio);

    // read the length of the ciphertext
    uint32_t cipherlen_net;
    memcpy(&cipherlen_net, message_M2 + offset, sizeof(uint32_t));
    cipherlen = ntohl(cipherlen_net);   // conversion in host byte order
    offset += sizeof(uint32_t);

    // read the ciphertext itself
    unsigned char* ciphertext = (unsigned char*)malloc(cipherlen);
    memcpy(ciphertext, message_M2 + offset, cipherlen);
    offset += cipherlen;

    // read the tag
    memcpy(tag, message_M2 + offset, TAG_SIZE);

    // free resources
    free(message_M2);

    // once we have parsed the message, the client can derive the shared secret:
    // initializing shared secret derivation context 
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(my_prvkey, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv, server_pubkey);

    // retrieving shared secret’s length
    size_t secretlen;
    EVP_PKEY_derive(ctx_drv, NULL, &secretlen);

    // deriving shared secret
    unsigned char* secret = (unsigned char*)malloc(secretlen);
    EVP_PKEY_derive(ctx_drv, secret, &secretlen);

    // once the shared secret is derived, the private key must be deleted
    EVP_PKEY_free(my_prvkey);

    // hash the shared secret to use it as a key for symmetric encryption:
    // context allocation
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    // buffer allocation for the digest
    sym_key = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));

    // hashing (initialization + single update + finalization)
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, secret, secretlen);
    EVP_DigestFinal(ctx, sym_key, NULL);

    // context deallocation 
    EVP_MD_CTX_free(ctx);

    // free resources
    free(secret);

    // now we must decrypt and verify the integrity of the message:
    // buffer allocation for the decrypted text
    unsigned char* signature = (unsigned char*)malloc(cipherlen);

    int signature_len;

    // construct the AAD fragment
    std::vector<unsigned char> AAD;
    AAD.insert(AAD.end(), (unsigned char*)&server_pubkey_len_net, (unsigned char*)&server_pubkey_len_net + sizeof(uint32_t));
    AAD.insert(AAD.end(), server_pubkey_raw, server_pubkey_raw + server_pubkey_len);
    AAD.insert(AAD.end(), (unsigned char*)&cipherlen_net, (unsigned char*)&cipherlen_net + sizeof(uint32_t));

    // decryption
    auth_decrypt(ciphertext, cipherlen, AAD.data(), AAD.size(), sym_key, iv, tag, signature, signature_len);

    // free resources
    free(ciphertext);

    // now, in order to authenticate the server, we must verify its digital signature on the pair of public keys:
    // context allocation
    ctx = EVP_MD_CTX_new();

    // construct the message to be verified: [server_pubkey || client_pubkey]
    std::vector<unsigned char> msg;
    msg.insert(msg.end(), server_pubkey_raw, server_pubkey_raw + server_pubkey_len);
    msg.insert(msg.end(), pubkey, pubkey + pubkey_len);

    // retrieve the server's RSA public key from the PEM file
    EVP_PKEY* RSA_server_pubkey;
    FILE* file = fopen("keys/server/rsa_server_pubkey.pem", "r");
    if(!file) 
    { 
        perror("Error while opening the PEM file of the server's public key");
        exit(1);
    }
    RSA_server_pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!RSA_server_pubkey)  
    { 
        printf("Error while reading the PEM file of the server's public key \n");
        exit(1);
    }
    fclose(file);

    // verification (initialization + single update + finalization)
    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx, msg.data(), msg.size());
    int ret = EVP_VerifyFinal(ctx, signature, signature_len, RSA_server_pubkey);
    if(ret != 1) 
    { 
        printf("Signature verification failed: invalid signature \n");
        exit(1);
    }

    // context deallocation
    EVP_MD_CTX_free(ctx);

    // free resources 
    free(signature);
    free(pubkey);
    BIO_free(pub_bio);

    // once the server has been correctly authenticated, we can proceed to send message M3:
    // first, the user must insert their credentials
    char* username = (char*)malloc(MAX_USR_SIZE);
    char* password = (char*)malloc(MAX_PWD_SIZE);
    printf("Insert your username: \n");
    scanf("%s", username);
    printf("Insert your password: \n");
    scanf("%s", password);

    // return the username
    username_out = username;

    // conversion in network byte order
    uint32_t username_len = htonl(strlen(username) + 1);
    uint32_t password_len = htonl(strlen(password) + 1);

    // construct the plaintext of message M3
    std::vector<unsigned char> message_M3_plain;
    message_M3_plain.insert(message_M3_plain.end(), (unsigned char*)&username_len, (unsigned char*)&username_len + sizeof(uint32_t));
    message_M3_plain.insert(message_M3_plain.end(), username, username + strlen(username) + 1);
    message_M3_plain.insert(message_M3_plain.end(), (unsigned char*)&password_len, (unsigned char*)&password_len + sizeof(uint32_t));
    message_M3_plain.insert(message_M3_plain.end(), password, password + strlen(password) + 1);
    message_M3_plain.insert(message_M3_plain.end(), server_pubkey_raw, server_pubkey_raw + server_pubkey_len);

    // generate the client's nonce
    RAND_bytes(nonce_c, NONCE_SIZE);

    // construct the whole message in the standard protocol format
    std::vector<unsigned char> message_M3;
    compose_std_message(message_M3_plain.data(), message_M3_plain.size(), nonce_c, sym_key, message_M3);

    // now we can send the message M3
    send_all(sd, message_M3.data(), message_M3.size());

    // free resources
    EVP_PKEY_free(server_pubkey); 

    // once the message M3 has been sent, we must wait for the client authentication result (message M4):
    unsigned char* message_M4;
    recv_all(sd, message_M4, len);

    // parsing of the message
    unsigned char* plaintext;
    parse_std_message(message_M4, sym_key, plaintext, nonce_s);

    // free resources
    free(message_M4);

    // return the last server's nonce
    memcpy(nonce, nonce_s, NONCE_SIZE);

    // parsing of the plaintext
    unsigned char received_nonce[NONCE_SIZE];
    bool auth_ok, pwd_change;
    memcpy(&auth_ok, plaintext, sizeof(bool));
    memcpy(&pwd_change, plaintext + sizeof(bool), sizeof(bool));
    memcpy(received_nonce, plaintext + 2 * sizeof(bool), NONCE_SIZE);

    // free resocurces
    free(plaintext);

    // check the freshness of the received nonce
    if(memcmp(received_nonce, nonce_c, NONCE_SIZE) != 0)
    {
        printf("Replay attack spotted: nonces do not match! \n");
        exit(1);
    }

    // verify the authentication result
    if(!auth_ok)
    {
        printf("Authentication failed: invalid username or password \n");
        exit(1);
    }

    // verify whether the password must be changed: if not, return; otherwise, change the password
    if(!pwd_change)
    {
        // securely clear the password from memory before freeing it
        explicit_bzero(password, MAX_PWD_SIZE);
        free(password);
        return;
    }

    char* new_password = (char*)malloc(MAX_PWD_SIZE);    
    char* password_repeated = (char*)malloc(MAX_PWD_SIZE); 

    printf("Since it's your first login, please enter a new password: \n");
    do {
        scanf("%s", new_password);

        if(strcmp(new_password, password) == 0)
        {
            printf("Password cannot be equal to the previous one, please try again \n");
            continue;
        }

        printf("Repeat the password: \n");
        scanf("%s", password_repeated);

        if(strcmp(new_password, password_repeated) != 0)
            printf("Passwords do not match, please try again \n");
        else 
            break;
    } 
    while(true);

    printf("Password updated successfully! \n");

    // conversion in network byte order
    password_len = htonl(strlen(new_password) + 1);

    // once the user has changed the password, we can send it to the server (message M5):
    // construct the plaintext
    std::vector<unsigned char> message_M5_plain;
    message_M5_plain.insert(message_M5_plain.end(), (unsigned char*)&password_len, (unsigned char*)&password_len + sizeof(uint32_t));
    message_M5_plain.insert(message_M5_plain.end(), (unsigned char*)new_password, (unsigned char*)new_password + strlen(new_password) + 1);
    message_M5_plain.insert(message_M5_plain.end(), nonce_s, nonce_s + NONCE_SIZE);

    // generate the client's nonce
    RAND_bytes(nonce_c, NONCE_SIZE);

    // construct the whole message in the standard protocol format
    std::vector<unsigned char> message_M5;
    compose_std_message(message_M5_plain.data(), message_M5_plain.size(), nonce_c, sym_key, message_M5);

    // now we can send the message M5
    send_all(sd, message_M5.data(), message_M5.size());

    // securely clear the passwords from memory before freeing it
    explicit_bzero(new_password, MAX_PWD_SIZE); 
    explicit_bzero(password_repeated, MAX_PWD_SIZE); 
    explicit_bzero(password, MAX_PWD_SIZE); 

    // free resources
    free(new_password);
    free(password_repeated);
    free(password);
}

// function that prepares the plaintext of the request starting from the buffer
std::vector<unsigned char> prepare_plaintext(char* buffer, const unsigned char* nonce_s, char*& command, char*& argument, bool& error)
{
    std::vector<unsigned char> plaintext;
    char* token;

    // split the buffer into tokens using space as delimiter
    token = strtok(buffer, DELIMITER);

    if(token != NULL)
    { 
        // insert the length of the command
        uint32_t command_len = htonl(strlen(token) + 1);    // conversion in network byte order
        plaintext.insert(plaintext.end(), (unsigned char*)&command_len, (unsigned char*)&command_len + sizeof(uint32_t));

        // insert the command itself
        plaintext.insert(plaintext.end(), (unsigned char*)token, (unsigned char*)token + strlen(token) + 1);
        command = token;

        token = strtok(NULL, DELIMITER);
    }      

    // insert the argument, if any
    if(token != NULL)
    {
        argument = token;

        // if the command is SignDoc, the argument contains the name of the file to be sent
        if(strcmp(command, "SignDoc") == 0)
        {
            // prepare the path of the document
            char path[MAX_PATH_SIZE];
            sprintf(path, "documents/%s", token);

            // open the file
            FILE* file = fopen(path, "rb");
            if(!file) 
            {
                printf("Error while opening the file '%s' \n", token);
                error = true;
                return plaintext;
            }

            // find the size of the file
            fseek(file, 0, SEEK_END);
            long size = ftell(file);
            rewind(file);

            // buffer allocation to store the file content
            unsigned char* buffer = (unsigned char*)malloc(size);

            // read the file
            fread(buffer, 1, size, file);

            // close the file
            fclose(file);

            // insert the size of the file
            uint32_t file_len = htonl(size);    // conversion in network byte order
            plaintext.insert(plaintext.end(), (unsigned char*)&file_len, (unsigned char*)&file_len + sizeof(uint32_t));

            // insert the file content
            plaintext.insert(plaintext.end(), (unsigned char*)buffer, (unsigned char*)buffer + size);
        }
        else // the command is GetPublicKey (the argument contains the username)
        {
            // insert the length of the argument
            uint32_t argument_len = htonl(strlen(token) + 1);    // conversion in network byte order
            plaintext.insert(plaintext.end(), (unsigned char*)&argument_len, (unsigned char*)&argument_len + sizeof(uint32_t));

            // insert the argument itself
            plaintext.insert(plaintext.end(), (unsigned char*)token, (unsigned char*)token + strlen(token) + 1);
        }
    }   
    else // in any case, send argument_len as 0 to make server parsing easier
    {
        uint32_t argument_len = 0;
        plaintext.insert(plaintext.end(), (unsigned char*)&argument_len, (unsigned char*)&argument_len + sizeof(uint32_t));
    }

    // insert the last server's nonce received
    plaintext.insert(plaintext.end(), nonce_s, nonce_s + NONCE_SIZE);    

    return plaintext;
}

int main(int argc, char** argv)
{
	int ret, sd, offset;
    uint32_t len;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in server_addr;

    // buffer allocation for nonces
    unsigned char nonce_c[NONCE_SIZE];
    unsigned char nonce_s[NONCE_SIZE];

    // socket creation
    sd = socket(AF_INET, SOCK_STREAM, 0);

    // server address creation
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family= AF_INET;
    server_addr.sin_port= htons(SERVER_PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    // connect to the server
    ret = connect(sd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if(ret < 0)
    {
        perror("Error while connecting");
        exit(1);
    }

    printf("Type 'Start' to establish a secure connection with the server \n");
    while(true)
    {
        // wait for user input
        fgets(buffer, BUFFER_SIZE, stdin);

        if(strcmp(buffer, "Start\n") != 0)
            printf("Invalid command: try again \n");
        else 
            break;    
    }

    // seed the PRNG
    RAND_poll();

    // estabilish a secure channel through the socket sd
    unsigned char* sym_key;
    char* username;
    handshake_protocol(sd, sym_key, nonce_s, username);

    printf("Secure connection established with the server! \n");

    // display the list of available commands
	print_menu();

    int c;
    // flush the stdin buffer by consuming characters until newline or EOF
    while((c = getchar()) != '\n' && c != EOF);

    while(true)
    {
        printf("\nType a command: \n");  

        // read an entire line from stdin
        fgets(buffer, BUFFER_SIZE, stdin);
        // remove newline character
        buffer[strcspn(buffer, "\n")] = '\0';  

        // prepare the request to be sent to the server:
        // prepare the plaintext
        char* command;
        char* argument;
        bool error = false;
        std::vector<unsigned char> plaintext_request = prepare_plaintext(buffer, nonce_s, command, argument, error);

        // skip to the next iteration if an error occurred during plaintext preparation
        if(error)
            continue;

        // generation of the client's nonce
        RAND_bytes(nonce_c, NONCE_SIZE);

        // construct the whole message in the standard protocol format
        std::vector<unsigned char> request;
        compose_std_message(plaintext_request.data(), plaintext_request.size(), nonce_c, sym_key, request);

        // send the request
        send_all(sd, request.data(), request.size());

        // if the user entered "Stop", free resources and exit
        if(strcmp(command, "Stop") == 0)
        {
            printf("Closing connection \n");
            free(sym_key);
            free(username);
            close(sd);
            exit(0);
        }

        // receive the response
        unsigned char* response;
        uint32_t response_len;
        recv_all(sd, response, response_len);
        
        // parse the response
        unsigned char* plaintext_response;
        parse_std_message(response, sym_key, plaintext_response, nonce_s);

        // free resources
        free(response);

        // parse the plaintext:
        // read the status
        uint8_t status;
        memcpy(&status, plaintext_response, sizeof(uint8_t));
        offset = sizeof(uint8_t);

        if(status == STATUS_INVALID_COMMAND)
            printf("Invalid command: please, try again \n");

        if(strcmp(command, "CreateKeys") == 0)
        {
            if(status == STATUS_LOGICAL_ERROR)
                printf("Error: keys already exist, or were deleted and cannot be recreated without offline registration \n");
            else if(status == STATUS_SUCCESS)
                printf("Success: RSA key pair correctly generated \n");
        }
        else if(strcmp(command, "SignDoc") == 0)
        {
            if(status == STATUS_LOGICAL_ERROR)
                printf("Error: no key found. Generate keys first \n");
            else if(status == STATUS_SUCCESS)
            {
                printf("Success: document signed correctly \n"); 

                // read the signature length
                memcpy(&len, plaintext_response + offset, sizeof(uint32_t));
                offset += sizeof(uint32_t);
                // conversion in host byte order
                uint32_t signature_len = ntohl(len);

                // read the signature itself
                unsigned char* signature = (unsigned char*)malloc(signature_len);
                memcpy(signature, plaintext_response + offset, signature_len);
                offset += signature_len;

                // save the signature in a binary file
                char path[MAX_PATH_SIZE];  

                // remove the directory path from the file name
                char* base_arg = strrchr(argument, '/');
                if (base_arg)
                    base_arg++;
                else
                    base_arg = argument;

                sprintf(path, "signatures/signature_%s_%s.bin", username, base_arg);
                FILE* sig_file = fopen(path, "wb");
                fwrite(signature, 1, signature_len, sig_file);
                fclose(sig_file);

                printf("Signature saved in 'signatures/signature_%s_%s.bin' \n", username, base_arg);

                // free resources 
                free(signature);
            }
        }
        else if(strcmp(command, "GetPublicKey") == 0)
        {
            if(status == STATUS_LOGICAL_ERROR)
                printf("Error: public key not found \n");
            else if(status == STATUS_SUCCESS)
            {
                printf("Success: public key retrieved correctly \n"); 

                // read the pubkey length
                memcpy(&len, plaintext_response + offset, sizeof(uint32_t));
                offset += sizeof(uint32_t);
                // conversion in host byte order
                uint32_t pubkey_len = ntohl(len);

                // read the pubkey itself
                unsigned char* pubkey = (unsigned char*)malloc(pubkey_len);
                memcpy(pubkey, plaintext_response + offset, pubkey_len);
                offset += pubkey_len;

                // save the user pubkey in a PEM file
                char path[MAX_PATH_SIZE];
                sprintf(path, "public_keys/%s_pubkey.pem", argument);
                FILE* pubkey_file = fopen(path, "wb");
                fwrite(pubkey, 1, pubkey_len, pubkey_file);
                fclose(pubkey_file);

                printf("Public key saved in 'public_keys/%s_pubkey.pem' \n", argument);

                // free resources
                free(pubkey);
            }
        }
        else if(strcmp(command, "DeleteKeys") == 0)
        {
            if(status == STATUS_LOGICAL_ERROR)
                printf("Error: no key to delete \n");
            else if(status == STATUS_SUCCESS)
                printf("Success: RSA key pair deleted \n");
        }

        // read the nonce
        unsigned char received_nonce[NONCE_SIZE];
        memcpy(received_nonce, plaintext_response + offset, NONCE_SIZE);

        // check the freshness of the response
        if(memcmp(received_nonce, nonce_c, NONCE_SIZE) != 0)
        {
            printf("Replay attack spotted: nonces do not match! \n");
            exit(1);
        }

        // free resources
        free(plaintext_response);
    }
}