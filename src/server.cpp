#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <vector>

#include <openssl/rsa.h>
#include <openssl/evp.h>   
#include <openssl/pem.h>   
#include <openssl/bio.h> 
#include <openssl/rand.h>

#include "../include/utils.hpp"
#include "../include/constants.hpp"

// utility constants for parsing 
#define MAX_LINE_LENGTH 512
#define DELIMITER "|"

// size of the salt
#define SALT_SIZE 16

// size of the hashed_password
#define HASHED_PWD_SIZE 32

// RSA constants
#define KEY_SIZE 3072
#define PUB_EXP 65537

// current number of active child processes
int children_count = 0;

// handler for the SIGUSR1 signal that decrements the number of active child processes
void handler(int sig)
{
    if(sig == SIGUSR1)
        children_count --; 
}

// function that prints the menu of commands accepted by the server
void print_menu()
{
    for(int i=0; i < 20; i++)
        printf("*");
   
    printf(" SERVER STARTED ");

    for(int i=0; i < 20; i++)
        printf("*");

    printf("\n");
    printf("Type a command: \n");
    printf("1) Start --> the DSS starts accepting connections \n");
    printf("2) Stop  --> the DSS shuts down \n");

    for(int i=0; i < 56; i++)
        printf("*");
    printf("\n");    
}

// function for hashing the passwords with a salt
void generate_hash(const char* password, const unsigned char* salt, unsigned char* hashed_password)
{
    PKCS5_PBKDF2_HMAC(
        password, strlen(password),
        salt, SALT_SIZE,
        100000,                             // number of iterations
        EVP_sha256(),                       // hashing algorithm
        HASHED_PWD_SIZE, hashed_password    // desired length + output
    );
}

// function to verify the client authentication
// returns true if the user is correctly authenticated (in this case, if pwd_change is true the password must be changed), otherwise returns false
bool client_authentication(const char* username, const char* password, bool& pwd_change)
{
    FILE* file = fopen("data/users.txt", "r");
    if(!file) 
    {
        perror("Errore while opening users.txt");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    char buffer[MAX_LINE_LENGTH];

    while(fgets(buffer, MAX_LINE_LENGTH, file)) 
    {
        // read the username
        char* token = strtok(buffer, DELIMITER);

        if(strcmp(token, username) == 0) // username found
        {
            // close the file 
            fclose(file);

            // read the salt field and convert from hex string to binary buffer
            char* salt_hex = strtok(NULL, DELIMITER);
            unsigned char* salt = OPENSSL_hexstr2buf(salt_hex, NULL);

            // read the hashed_password field and convert from hex string to binary buffer
            char* hash_hex = strtok(NULL, DELIMITER);
            unsigned char* hashed_password = OPENSSL_hexstr2buf(hash_hex, NULL);

            // read the first_login_flag field as a string and convert it to int
            char* flag_str = strtok(NULL, DELIMITER);
            int first_login_flag = atoi(flag_str);  

            pwd_change = first_login_flag;

            // hash the password to compare with stored hash:
            // buffer allocation for the digest
            unsigned char input_hashed_password[HASHED_PWD_SIZE];

            // hashing
            generate_hash(password, salt, input_hashed_password);

            // check whether the hashed passwords match
            bool auth_ok = (CRYPTO_memcmp(input_hashed_password, hashed_password, HASHED_PWD_SIZE) == 0);
               
            // free resources
            OPENSSL_free(salt);
            OPENSSL_free(hashed_password);

            return auth_ok;
        }
    }

    fclose(file);
    return false;   // username not found
}

// function to update the password in users.txt of the user specified
void update_pwd(const char* username, const char* new_password)
{
    FILE* src = fopen("data/users.txt", "r");
    if(!src) 
    {
        perror("Errore while opening users.txt");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    // temporary file 
    char temp_filename[] = "tempfileXXXXXX";
    int fd = mkstemp(temp_filename);
    FILE *dst = fdopen(fd, "w");
    if(!dst) 
    {
        perror("Errore while opening the temporary file");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    // compute the new hashed_password with a new salt
    unsigned char salt[SALT_SIZE];
    RAND_bytes(salt, SALT_SIZE);
    unsigned char new_hashed_password[HASHED_PWD_SIZE];
    generate_hash(new_password, salt, new_hashed_password);

    // convert them from binary buffer to hex string
    char* salt_hex = OPENSSL_buf2hexstr(salt, SALT_SIZE);
    char* hash_hex = OPENSSL_buf2hexstr(new_hashed_password, HASHED_PWD_SIZE);

    // create the new line for the user specified (with the flag set to 0)
    char new_line[MAX_LINE_LENGTH];
    sprintf(new_line, "%s|%s|%s|%d\n", username, salt_hex, hash_hex, 0);

    // free resources
    OPENSSL_free(salt_hex);
    OPENSSL_free(hash_hex);

    char buffer[MAX_LINE_LENGTH];
    while(fgets(buffer, sizeof(buffer), src)) 
    {
        // copy the buffer since strtok modifies it
        char line_copy[MAX_LINE_LENGTH];
        strcpy(line_copy, buffer);

        char* current_user = strtok(line_copy, DELIMITER);
        if(strcmp(current_user, username) == 0) 
            fputs(new_line, dst);  // write the new line
        else
            fputs(buffer, dst);    // otherwise copy the original line
    }

    // free resources
    fclose(src);
    fclose(dst);

    // substitute the original file with the new one
    rename(temp_filename, "data/users.txt");

    printf("Password for the user '%s' updated successfully! \n", username);
}

// function that establishes a secure channel and returns the server's last nonce and the client's credentials (used to identify the user in subsequent requests)
void handshake_protocol(int sd, unsigned char*& sym_key, unsigned char* nonce, char*& username_out, char*& password_out)
{
    // utility variables 
    uint32_t len;
    int cipherlen, offset;

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
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    // read DH parameters
    dh_params = PEM_read_bio_Parameters(bio, NULL);
    if(!dh_params) 
    {
        perror("Error reading DH parameters from dhparam.pem");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
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

    // receive the client's message M1
    unsigned char* client_pubkey_raw;
    uint32_t client_pubkey_len;
    recv_all(sd, client_pubkey_raw, client_pubkey_len);

    bio = BIO_new_mem_buf(client_pubkey_raw, client_pubkey_len);

    // load the public key from the BIO into an EVP_PKEY structure
    EVP_PKEY* client_pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    // now the server can derive the shared secret:
    // initializing shared secret derivation context 
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(my_prvkey, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv, client_pubkey);

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

    // once the session key is estabilished, the server can proceed to construct the message M2:
    // first, compose the pair of public keys  
    std::vector<unsigned char> pubkey_pair;
    pubkey_pair.insert(pubkey_pair.end(), pubkey, pubkey + pubkey_len);
    pubkey_pair.insert(pubkey_pair.end(), client_pubkey_raw, client_pubkey_raw + client_pubkey_len);

    // free resources
    free(client_pubkey_raw);

    // retrieve the server's RSA private key from the PEM file
    EVP_PKEY* RSA_server_privkey;
    FILE* file = fopen("keys/server/rsa_server_privkey.pem", "r");
    if(!file) 
    { 
        perror("Error while opening the PEM file of the server's private key");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    RSA_server_privkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    if(!RSA_server_privkey)  
    { 
        printf("Error while reading the PEM file of the server's private key \n");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    fclose(file);

    // digitally sign the pair of public keys:
    // buffer allocation for the signature
    unsigned char* signature = (unsigned char*)malloc(EVP_PKEY_size(RSA_server_privkey));
    uint32_t signature_len;

    // context allocation
    ctx = EVP_MD_CTX_new();

    // signature generation (initialization + single update + finalization)
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, pubkey_pair.data(), pubkey_pair.size());
    EVP_SignFinal(ctx, signature, &signature_len, RSA_server_privkey);

    // context deallocation
    EVP_MD_CTX_free(ctx);

    // after having digitally signed the pair of public keys, we must encrypt the signature by means of the symmetric key and compose the whole message:
    // buffer allocation for the ciphertext
    unsigned char* ciphertext = (unsigned char*)malloc(signature_len);

    // generate the IV
    RAND_bytes(iv, IV_SIZE);

    // conversion in network byte order
    uint32_t cipherlen_net = htonl(signature_len); 
    uint32_t pubkey_len_net = htonl(pubkey_len);

    // construct the AAD
    std::vector<unsigned char> AAD;
    AAD.insert(AAD.end(), (unsigned char*)&pubkey_len_net, (unsigned char*)&pubkey_len_net + sizeof(uint32_t));
    AAD.insert(AAD.end(), pubkey, pubkey + pubkey_len);
    AAD.insert(AAD.end(), (unsigned char*)&cipherlen_net, (unsigned char*)&cipherlen_net + sizeof(uint32_t));

    // encryption
    auth_encrypt(signature, signature_len, AAD.data(), AAD.size(), sym_key, iv, tag, ciphertext, cipherlen);

    // construct the message to be sent
    std::vector<unsigned char> message_M2;
    message_M2.insert(message_M2.end(), iv, iv + IV_SIZE);
    message_M2.insert(message_M2.end(), (unsigned char*)&pubkey_len_net, (unsigned char*)&pubkey_len_net + sizeof(uint32_t));
    message_M2.insert(message_M2.end(), pubkey, pubkey + pubkey_len);
    message_M2.insert(message_M2.end(), (unsigned char*)&cipherlen_net, (unsigned char*)&cipherlen_net + sizeof(uint32_t));
    message_M2.insert(message_M2.end(), ciphertext, ciphertext + cipherlen);
    message_M2.insert(message_M2.end(), tag, tag + TAG_SIZE);

    // now we can send the message M2
    send_all(sd, message_M2.data(), message_M2.size());

    // free resources
    free(ciphertext);

    // receive the client's message M3
    unsigned char* message_M3;
    recv_all(sd, message_M3, len);

    // parsing of the message
    unsigned char* plaintext;
    parse_std_message(message_M3, sym_key, plaintext, nonce_c);

    // free resources
    free(message_M3);

    // parsing of the plaintext:
    // read the length of the username
    uint32_t username_len;
    memcpy(&len, plaintext, sizeof(uint32_t));
    username_len = ntohl(len); // conversion in host byte order
    offset = sizeof(uint32_t);

    // read the username itself
    char* username = (char*)malloc(username_len);
    memcpy(username, plaintext + offset, username_len);
    offset += username_len;

    // read the length of the password
    uint32_t password_len;
    memcpy(&len, plaintext + offset, sizeof(uint32_t));
    password_len = ntohl(len); // conversion in host byte order
    offset += sizeof(uint32_t);

    // read the password itself
    char* password = (char*)malloc(password_len);
    memcpy(password, plaintext + offset, password_len);
    offset += password_len;

    // read the server's public key (used here as a nonce)
    unsigned char* received_pubkey = (unsigned char*)malloc(pubkey_len);
    memcpy(received_pubkey, plaintext + offset, pubkey_len);

    // check the freshness of the received nonce
    if(memcmp(received_pubkey, pubkey, pubkey_len) != 0)
    {
        printf("Replay attack spotted: nonces do not match! \n");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    // free resources
    free(plaintext);
    BIO_free(pub_bio);

    // once the message has been parsed, we have to verify the client authentication using its credentials
    bool auth_ok, pwd_change;
    auth_ok = client_authentication(username, password, pwd_change);

    // return both username and password
    username_out = username;
    password_out = password;

    // construct the plaintext of message M4
    std::vector<unsigned char> message_M4_plain;
    message_M4_plain.insert(message_M4_plain.end(), (unsigned char*)&auth_ok, (unsigned char*)&auth_ok + sizeof(bool));
    message_M4_plain.insert(message_M4_plain.end(), (unsigned char*)&pwd_change, (unsigned char*)&pwd_change + sizeof(bool));
    message_M4_plain.insert(message_M4_plain.end(), nonce_c, nonce_c + NONCE_SIZE);

    // generate the server's nonce
    RAND_bytes(nonce_s, NONCE_SIZE);

    // return the last server's nonce
    memcpy(nonce, nonce_s, NONCE_SIZE);

    // construct the whole message in the standard protocol format
    std::vector<unsigned char> message_M4;
    compose_std_message(message_M4_plain.data(), message_M4_plain.size(), nonce_s, sym_key, message_M4);

    // now we can send the message M4
    send_all(sd, message_M4.data(), message_M4.size());

    // verify the authentication result
    if(!auth_ok)
    {
        printf("Authentication failed: the client has inserted invalid username or password \n");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    printf("Authentication successful: valid username and password provided \n");

    // verify whether the password must be changed: if not, return; otherwise, wait for the client's message M5
    if(!pwd_change)
        return;

    // free resources
    free(password); 

    // receive the client's message M5
    unsigned char* message_M5;
    recv_all(sd, message_M5, len);

    // parsing of the message
    parse_std_message(message_M5, sym_key, plaintext, nonce_c);

    // free resources
    free(message_M5);

    // parsing of the plaintext:
    // read the length of the password
    memcpy(&len, plaintext, sizeof(uint32_t));
    password_len = ntohl(len); // conversion in host byte order
    offset = sizeof(uint32_t);

    // read the password itself
    char* new_password = (char*)malloc(password_len);
    memcpy(new_password, plaintext + offset, password_len);
    offset += password_len;

    // read the server's nonce
    unsigned char received_nonce[NONCE_SIZE];
    memcpy(received_nonce, plaintext + offset, NONCE_SIZE);

    // free resocurces
    free(plaintext);

    // check the freshness of the received nonce
    if(memcmp(received_nonce, nonce_s, NONCE_SIZE) != 0)
    {
        printf("Replay attack spotted: nonces do not match! \n");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    // now we have to update the client's password in users.txt
    update_pwd(username, new_password);

    // return the new password
    password_out = new_password;
}

// helper function to verify if a file exists
bool file_exists(const char* path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

// function that creates and stores a pair of RSA private and public keys on behalf of the invoking user
bool create_keys(const char* username, const char* password)
{
    EVP_PKEY* pkey = NULL;
    char user_dir[MAX_USER_DIR_SIZE], priv_path[MAX_PATH_SIZE], pub_path[MAX_PATH_SIZE];

    // prepare user directory paths
    snprintf(user_dir, sizeof(user_dir), "keys/users/%s", username);
    snprintf(priv_path, sizeof(priv_path), "%s/rsa_priv_enc.pem", user_dir);
    snprintf(pub_path, sizeof(pub_path), "%s/rsa_pub.pem", user_dir);

    // if the private key already exists, return false
    if(file_exists(priv_path)) 
    {
        printf("Keys for user '%s' already exist, no regeneration needed \n", username);
        return false;
    }

    // if the user is into the revoked list, return false
    FILE* file = fopen("data/revoked.txt", "r");
    if(!file) 
    { 
        perror("Error while opening revoked.txt");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    char buffer[BUFFER_SIZE];
    while(fgets(buffer, sizeof(buffer), file)) 
    {
        buffer[strcspn(buffer, "\n")] = 0; // remove newline
        if(strcmp(buffer, username) == 0) 
        {
            fclose(file);
            printf("User '%s' is revoked, cannot create keys \n", username);
            return false; 
        }
    }
    fclose(file);

    // create the user directory
    mkdir(user_dir, 0700);

    // generate RSA keys
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if(!ctx || EVP_PKEY_keygen_init(ctx) <= 0) 
    {
        printf("EVP_PKEY context init failed\n");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_SIZE) <= 0) 
    {
        printf("EVP_PKEY set keygen bits failed\n");
        EVP_PKEY_CTX_free(ctx);
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    if(EVP_PKEY_keygen(ctx, &pkey) <= 0) 
    {
        printf("EVP_PKEY key generation failed\n");
        EVP_PKEY_CTX_free(ctx);
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    EVP_PKEY_CTX_free(ctx);

    // save encrypted private key
    FILE* priv_fp = fopen(priv_path, "wb");
    if(!priv_fp) 
    {
        perror("Failed to open private key file");
        EVP_PKEY_free(pkey);
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    if(!PEM_write_PrivateKey(priv_fp, pkey, EVP_aes_256_cbc(), (unsigned char*)password, strlen(password), NULL, NULL)) 
    {
        printf("Failed to write private key \n");
        fclose(priv_fp);
        EVP_PKEY_free(pkey);
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    fclose(priv_fp);

    // save public key
    FILE* pub_fp = fopen(pub_path, "wb");
    if(!pub_fp) 
    {
        perror("Failed to open public key file");
        EVP_PKEY_free(pkey);
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    if(!PEM_write_PUBKEY(pub_fp, pkey)) 
    {
        printf("Failed to write public key \n");
        fclose(pub_fp);
        EVP_PKEY_free(pkey);
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    fclose(pub_fp);

    // free resources
    EVP_PKEY_free(pkey);

    printf("RSA key pair for user '%s' saved in '%s/'\n", username, user_dir);
    return true;
}

// function that returns the public key of the user specified as argument
bool get_public_key(const char* username, unsigned char*& pubkey, uint32_t& pubkey_len)
{
    // prepare the path of the key, if exists 
    char path[MAX_PATH_SIZE];
    snprintf(path, sizeof(path), "keys/users/%s/rsa_pub.pem", username);

    // if the key does not exist, return false
    if(!file_exists(path)) 
    {
        printf("Public key for user '%s' does not exist \n", username);
        return false;
    }

    // retrieve the user's RSA public key from the PEM file
    EVP_PKEY* RSA_pubkey;
    FILE* file = fopen(path, "r");
    if(!file) 
    { 
        perror("Error while opening the PEM file of the user's public key");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    RSA_pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if(!RSA_pubkey)  
    { 
        printf("Error while reading the PEM file of the user's public key \n");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    fclose(file);

    // convert the key into a raw unsigned char buffer
    BIO* mem = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mem, RSA_pubkey);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);

    // pubkey buffer allocation
    pubkey = (unsigned char*)malloc(bptr->length);
    memcpy(pubkey, bptr->data, bptr->length);
    
    // save the pubkey length
    pubkey_len = bptr->length;

    // free resources
    EVP_PKEY_free(RSA_pubkey);
    BIO_free(mem);

    printf("Public key for user '%s' retrieved successfully \n", username);
    return true;
}

// function that deletes the key pair of the invoking user and adds the user to the revoked list to prevent future key creation
bool delete_keys(const char* username)
{
    int ret;

    // prepare the paths of the key pair, if exist 
    char user_dir[MAX_USER_DIR_SIZE], pub_path[MAX_PATH_SIZE], priv_path[MAX_PATH_SIZE];
    snprintf(user_dir, sizeof(user_dir), "keys/users/%s", username);
    snprintf(pub_path, sizeof(pub_path), "%s/rsa_pub.pem", user_dir);
    snprintf(priv_path, sizeof(priv_path), "%s/rsa_priv_enc.pem", user_dir);

    // if the keys do not exist, return false
    if(!file_exists(user_dir))
    {
        printf("Keys for user '%s' do not exist \n", username);
        return false;
    }

    // delete public key
    ret = remove(pub_path);
    if(ret != 0)
    {
        perror("Failed to delete public key");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    // delete private key
    ret = remove(priv_path);
    if(ret != 0)
    {
        perror("Failed to delete private key");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    // delete the user directory
    ret = rmdir(user_dir);
    if(ret != 0)
    {
        perror("Failed to delete user directory");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    // insert the user into the revoked.txt file 
    FILE* file = fopen("data/revoked.txt", "a");
    if(!file) 
    { 
        perror("Error while opening revoked.txt");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    fprintf(file, "%s\n", username);
    fclose(file);

    printf("RSA key pair for user '%s' deleted successfully \n", username);
    return true;
}

// function that digitally signs the document specified as argument on the invoking user’s behalf
// and returns him/her the resulting digital signature
bool sign_doc(const char* username, const char* password, const unsigned char* document, uint32_t document_len, unsigned char*& signature, uint32_t& signature_len)
{
    // prepare the path of the user's private key
    char priv_path[MAX_PATH_SIZE];
    snprintf(priv_path, sizeof(priv_path), "keys/users/%s/rsa_priv_enc.pem", username);

    // if the key do not exist, return false
    if(!file_exists(priv_path))
    {
        printf("Cannot sign document: private key for user '%s' does not exist \n", username);
        return false;
    }

    // retrieve the user's RSA private key from the PEM file
    EVP_PKEY* RSA_privkey;
    FILE* file = fopen(priv_path, "r");
    if(!file) 
    { 
        perror("Error while opening the PEM file of the user's private key");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }
    RSA_privkey = PEM_read_PrivateKey(file, NULL, NULL, (void*)password);
    if(!RSA_privkey)  
    { 
        printf("Error while reading the encrypted PEM file of the user's private key: ");
        printf("this might be caused by an incorrect password or a corrupted file. \n");
        return false;
    }
    fclose(file);

    // digitally sign the document:
    // buffer allocation for the signature
    signature = (unsigned char*)malloc(EVP_PKEY_size(RSA_privkey));

    // context allocation
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // signature generation (initialization + single update + finalization)
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, document, document_len);
    EVP_SignFinal(ctx, signature, &signature_len, RSA_privkey);

    // context deallocation
    EVP_MD_CTX_free(ctx);

    printf("The document has been successfully signed with the private key of the user '%s'\n", username);
    return true;
}

// function that prepares the plaintext of the response starting from the plaintext of the request (and check the freshness of the latter)
std::vector<unsigned char> prepare_response(const unsigned char* plaintext_request, const unsigned char* nonce_s, const unsigned char* nonce_c, char* username, char* password, unsigned char* key)
{
    int offset;
    uint32_t len, argument_len;;
    uint8_t status = STATUS_SUCCESS;
    char* argument = nullptr;
    std::vector<unsigned char> plaintext_response;

    // parse the plaintext of the request:
    // read the length of the command
    uint32_t command_len;
    memcpy(&len, plaintext_request, sizeof(uint32_t));
    command_len = ntohl(len);   // conversion in host byte order
    offset = sizeof(uint32_t);

    // read the command itself
    char* command = (char*)malloc(command_len);
    memcpy(command, plaintext_request + offset, command_len);
    offset += command_len;

    // read the length of the argument 
    memcpy(&len, plaintext_request + offset, sizeof(uint32_t));
    argument_len = ntohl(len);   // conversion in host byte order
    offset += sizeof(uint32_t);

    // validate the argument based on the command
    if(strcmp(command, "SignDoc") == 0 || strcmp(command, "GetPublicKey") == 0)
    {
        if(argument_len == 0)
        {
            status = STATUS_INVALID_COMMAND; // required argument missing
        }
        else
        {
            // read the argument
            argument = (char*)malloc(argument_len);
            memcpy(argument, plaintext_request + offset, argument_len);
            offset += argument_len;
        }
    }
    else if(strcmp(command, "Stop") == 0 || strcmp(command, "CreateKeys") == 0 || strcmp(command, "DeleteKeys") == 0)
    {
        if(argument_len != 0)
        {
            status = STATUS_INVALID_COMMAND; // argument not expected
            offset += argument_len;
        }    
    }
    else
    {
        status = STATUS_INVALID_COMMAND; // unknown command
    }

    // read the nonce 
    unsigned char received_nonce[NONCE_SIZE];
    memcpy(received_nonce, plaintext_request + offset, NONCE_SIZE);

    // check the freshness of the received nonce
    if(memcmp(received_nonce, nonce_s, NONCE_SIZE) != 0)
    {
        printf("Replay attack spotted: nonces do not match! \n");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    // execute the command entered by the user and prepare the corresponding plaintext
    if(status != STATUS_INVALID_COMMAND)
    {
        if(strcmp(command, "CreateKeys") == 0)
        {
            status = create_keys(username, password);
        }
        else if(strcmp(command, "SignDoc") == 0)
        {
            unsigned char* signature = nullptr;
            uint32_t signature_len, signature_len_net;
            status = sign_doc(username, password, (unsigned char*)argument, argument_len, signature, signature_len);

            if(status != STATUS_LOGICAL_ERROR)
            {
                // conversion in network byte order
                signature_len_net = htonl(signature_len);

                plaintext_response.insert(plaintext_response.end(), (unsigned char*)&signature_len_net, (unsigned char*)&signature_len_net + sizeof(uint32_t));
                plaintext_response.insert(plaintext_response.end(), signature, signature + signature_len);
            }

            if(signature) free(signature);
        }
        else if(strcmp(command, "GetPublicKey") == 0) 
        {
            unsigned char* pubkey = nullptr;
            uint32_t pubkey_len, pubkey_len_net;
            status = get_public_key(argument, pubkey, pubkey_len);

            if(status != STATUS_LOGICAL_ERROR)
            {
                // conversion in network byte order
                pubkey_len_net = htonl(pubkey_len);

                plaintext_response.insert(plaintext_response.end(), (unsigned char*)&pubkey_len_net, (unsigned char*)&pubkey_len_net + sizeof(uint32_t));
                plaintext_response.insert(plaintext_response.end(), pubkey, pubkey + pubkey_len);
            }

            if(pubkey) free(pubkey);
        }
        else if(strcmp(command, "DeleteKeys") == 0)
        {
            status = delete_keys(username);
        }
        else if(strcmp(command, "Stop") == 0)
        {
            printf("Closing connection with '%s' \n", username);

            // securely clear the password from memory before freeing it
            explicit_bzero(password, MAX_PWD_SIZE);
            // free resources
            free(password);
            free(key);
            free(username);

            // send the signal to the parent process
            pid_t pid = getppid();
            kill(pid, SIGUSR1);
            // terminate the process
            exit(0);
        }
    }

    // insert status at the beginning
    plaintext_response.insert(plaintext_response.begin(), (unsigned char*)&status, (unsigned char*)&status + sizeof(uint8_t));

    // insert the client's nonce
    plaintext_response.insert(plaintext_response.end(), nonce_c, nonce_c + NONCE_SIZE);  
    
    // free resources
    free(command);
    if(argument) free(argument);
        
    return plaintext_response;
}

int main(int argc, char** argv)
{
	int ret, sd, new_sd, len, port_number;
    pid_t pid;
	char buffer[BUFFER_SIZE];
    fd_set read_fds;
    struct sockaddr_in my_addr, client_addr;

    if(argc > 1)
		port_number = atoi(argv[1]);

    // socket creation
    sd = socket(AF_INET, SOCK_STREAM, 0);

    // address creation
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family= AF_INET;
    my_addr.sin_port= htons(port_number);
    inet_pton(AF_INET, "127.0.0.1", &my_addr.sin_addr);
        
    ret = bind(sd, (struct sockaddr*)&my_addr, sizeof(my_addr));
    ret = listen(sd, 10);
    if(ret < 0)
    {
        perror("errore during bind");
        // send the signal to the parent process
        pid_t pid = getppid();
        kill(pid, SIGUSR1);
        exit(1);
    }

    // display the list of available commands
	print_menu();
    
    while(true)
    {
        // wait for user input
        scanf("%s", buffer);

        if(strcmp(buffer, "Start") == 0)
        {
            printf("Starting accepting connections \n");

            // associate this handler with the arrival of the SIGUSR1 signal, which will decrement the variable children_count
            signal(SIGUSR1, handler);

            while(true)
            {
                // use the select() primitive to monitor ready descriptors,
                // in this case stdin to read a possible command typed by the user,
                // and the listening socket to accept a new request from a client
                FD_ZERO(&read_fds);
                FD_SET(STDIN_FILENO, &read_fds);
                FD_SET(sd, &read_fds);

                // blocking select, it returns only when one of the two descriptors is ready for reading
                ret = select(sd + 1, &read_fds, NULL, NULL, NULL);

                // stdin is ready
                if(FD_ISSET(STDIN_FILENO, &read_fds))
                {
                    ret = read(STDIN_FILENO, buffer, BUFFER_SIZE);
                    buffer[ret] = '\0';

                    // the user typed the "Stop" command
                    if (strcmp(buffer, "Stop\n") == 0)
                    {
                        if(children_count == 0)
                        {
                            printf("Shutting down the server \n");
                            close(sd);
                            exit(0);
                        }
                        printf("Unable to shut down the server: there are %d active connections \n", children_count);
                    }
                    else if (strcmp(buffer, "Start\n") == 0)
                        printf("Server already running! \n");
                    else    
                        printf("Invalid command, try again! \n");
                }
                else // listening socket is ready, so there is a new request from a client
                {
                    len = sizeof(client_addr);
                    new_sd = accept(sd, (struct sockaddr*)&client_addr, (socklen_t*)&len);
                    pid = fork();

                    if(pid == -1)
                    {
                        perror("Error during fork");
                        exit(1);
                    }
                    if(pid == 0)
                    {
                        // child process
                        close(sd);

                        // buffer allocation for nonces
                        unsigned char nonce_c[NONCE_SIZE];
                        unsigned char nonce_s[NONCE_SIZE];

                        // seed the PRNG
                        RAND_poll();

                        // estabilish a secure channel through the communication socket new_sd
                        unsigned char* sym_key;
                        char* username, *password;
                        handshake_protocol(new_sd, sym_key, nonce_s, username, password);  

                        printf("Secure connection established with the user '%s'! \n", username);

                        while(true)
                        {
                            // receive the request from the client
                            unsigned char* request;
                            uint32_t request_len;
                            recv_all(new_sd, request, request_len);

                            // parse the request
                            unsigned char* plaintext_request;
                            parse_std_message(request, sym_key, plaintext_request, nonce_c);

                            // free resources
                            free(request);

                            // parse the request plaintext and prepare the response plaintext
                            std::vector<unsigned char> plaintext_response = prepare_response(plaintext_request, nonce_s, nonce_c, username, password, sym_key); 

                            // generation of the server's nonce
                            RAND_bytes(nonce_s, NONCE_SIZE);

                            // construct the whole message in the standard protocol format
                            std::vector<unsigned char> response;
                            compose_std_message(plaintext_response.data(), plaintext_response.size(), nonce_s, sym_key, response);

                            // send the response
                            send_all(new_sd, response.data(), response.size());

                            // free resources 
                            free(plaintext_request);
                        }
                    }

                    // parent process
                    children_count ++;
                    close(new_sd);
                }
            }
        }
        else if(strcmp(buffer, "Stop") == 0)
        {
            printf("Shutting down the server \n");
            close(sd);
            exit(0);
        }
        else 
            printf("Invalid command, try again! \n");
    }    
}