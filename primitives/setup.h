#ifndef SETUP_H
#define SETUP_H

//#include "primitves.h"

#include "../primitives/primitives.h"
#include "socket.h"
#include <set>

#define INPUT_4M 512
//#define INPUT_PER_SHARE 256/12
//#define INPUT_FIRST_SHARE 256/4 - 2 * INPUT_PER_SHARE


//id for A,B,C,D,E is 0,1,2,3,4 respectively.


void verifyRecvdCom(unsigned char * out2, unsigned char * msg, int size, int id, int fromid);
void genCommit(unsigned char my_Commit[4][SHA256_DIGEST_LENGTH], u_char my_Decommit[4][SHA256_DIGEST_LENGTH], int id, bool inputs[INPUT_4M]);
void sendOpenings(unsigned char my_Commit[3][SHA256_DIGEST_LENGTH], unsigned char my_Decommit[3][SHA256_DIGEST_LENGTH], int id);
void recvOpenings(unsigned char recvd_commitment[4][4][SHA256_DIGEST_LENGTH], unsigned char recvd_open[4][4][SHA256_DIGEST_LENGTH], int id, int fromid);
void verifyRecvdCom(unsigned char * out2, unsigned char * msg, int size, int id, int fromid);
void recvCommitments(unsigned char recvd_commitment[4][4][SHA256_DIGEST_LENGTH], int id, int fromid);
void sendComR2(unsigned char recvd_commitment[4][4][SHA256_DIGEST_LENGTH], int id);
void sendOpenR2(unsigned char recvd_open[4][4][SHA256_DIGEST_LENGTH], int id, int toid);
void recvCommitmentsR2(unsigned char recvd_commitmentR2[4][4][4][SHA256_DIGEST_LENGTH], int id, int fromid);
void chooseMajority(unsigned char recvd_commitment[4][4][SHA256_DIGEST_LENGTH], unsigned char recvd_commitmentR2[4][4][4][SHA256_DIGEST_LENGTH], unsigned char commit_majority_[4][4][SHA256_DIGEST_LENGTH], unsigned char open_majority_[4][4][SHA256_DIGEST_LENGTH], int id);
void recvOpeningsR2(unsigned char recvd_openR2[4][4][SHA256_DIGEST_LENGTH], int id, int fromid, int toid);
void chooseMajorityOpen(unsigned char recvd_open[4][4][SHA256_DIGEST_LENGTH], unsigned char recvd_openR2[4][4][SHA256_DIGEST_LENGTH], unsigned char commit_majority_[4][4][SHA256_DIGEST_LENGTH], unsigned char open_majority_[4][4][SHA256_DIGEST_LENGTH], int id);

#endif
