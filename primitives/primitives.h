
#ifndef PRIMITIVES_H
#define PRIMITIVES_H

#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <msgpack.h>
#include <emmintrin.h>

extern "C"{
#include "../libgarble/garble.h"
#include "../libgarble/garble/block.h"
#include "../libgarble/utils.h"
}

#include <iostream>
#include <fstream>
#include <utility>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <thread>
#include <mutex>
#include <ctime>
using namespace std;

#define BUF_SIZE 2000
#define AES128_3PC_CIRCUIT_FILE "circuits/AES128"
#define SERVER_PORT 7868
#define SERVER_PORT2 7839
#define SERVER_PORT3 7876
#define FIXED_SEED 135

typedef unsigned char u_char;


#define COMMIT_SCHEME_SHA256 1
typedef char * commitment;
typedef char sha256_block[SHA256_DIGEST_LENGTH];

void commit(commitment output, block msg, void *rand, int scheme_type);
bool verify_commit(commitment c, block msg, void *rand, int scheme_type);
bool compare_commit(char *msg1 ,char *msg2, int length);

void commitInputs(unsigned char * output, unsigned char * msg, size_t size, void *rand, int scheme_type);
bool verify_commitInputs(unsigned char * out2, unsigned char * msg, size_t size, void *rand, int scheme_type);

long long current_time();

void randomGen(unsigned char *key, int size);

// void printHex(u_char *msg_ptr , int msg_size);
void print128_num(block var);

void writeToFile(u_char *msg,char *file_name,int size);
ssize_t broadcast(int sockfd1,int socfd2, const void *buf, size_t len ,int flags);
void readFromFile(u_char *msg,char *file_name);
extern "C"{
void build(garble_circuit *gc, char* file);
}
#endif //PRIMITIVES_H
