#pragma once

// size of the buffer
#define BUFFER_SIZE 1024

// size of the initialization vector
#define IV_SIZE 12

// size of the tag
#define TAG_SIZE 16

// size of the nonce
#define NONCE_SIZE 16

// max size of username and password
#define MAX_USR_SIZE 32
#define MAX_PWD_SIZE 128

// maximux size of the paths
#define MAX_PATH_SIZE 160
#define MAX_USER_DIR_SIZE 128

// status codes
#define STATUS_SUCCESS 1
#define STATUS_LOGICAL_ERROR 0
#define STATUS_INVALID_COMMAND 2