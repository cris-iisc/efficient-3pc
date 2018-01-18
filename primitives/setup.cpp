#include "setup.h"

int INPUT_PER_SHARE_ = INPUT_4M/12;
int IINPUT_FIRST_SHARE_ = INPUT_4M/4 - 2 * INPUT_PER_SHARE_;

//std::set<int> *P = new std::set<int> [4];
 int arrP_[4][3]={
 					{1,2,3},
 					{0,2,3},
 					{0,1,3},
 					{0,1,2}
				 };

std::set<int> *corrupt_set_ = new std::set<int> [4];
std::set<int> *conflict_sets_ = new std::set<int> [4];

/*unsigned char commit_majority_[4][4][SHA256_DIGEST_LENGTH];
unsigned char open_majority_[4][4][SHA256_DIGEST_LENGTH];

unsigned char recvd_commitment[4][4][SHA256_DIGEST_LENGTH]; //4 parties, each has 3 commitments, each commitment is 256bits
unsigned char recvd_commitmentR2[4][4][4][SHA256_DIGEST_LENGTH]; //4 parties, each has 3 commitments, each commitment is 256bits
unsigned char recvd_open[4][4][SHA256_DIGEST_LENGTH]; //4 parties each has two shares
unsigned char recvd_openR2[4][4][SHA256_DIGEST_LENGTH]; //4 parties each has two shares
//bool inputs[INPUT_4M];
unsigned char my_Commit[4][SHA256_DIGEST_LENGTH]; //gen commitment for 3 shares
unsigned char my_Decommit[4][SHA256_DIGEST_LENGTH]; //decommitment for 3 shares*/
int TS[4][4][2] ={
					{
						{0,0},
						{2,3},
						{1,3},
						{1,2}
					},

					{
						{2,3},
						{0,0},
						{0,3},
						{0,2}
					},

					{
						{1,3},
						{0,3},
						{0,0},
						{0,1}
					},

					{
						{1,2},
						{0,2},
						{0,1},
						{0,0}
					},

				}; //Tij array

unsigned char buffer1[MAX_PAYLOAD_SIZE];



//generate commitments, save openings and send
void genCommit(unsigned char my_Commit[4][SHA256_DIGEST_LENGTH], u_char my_Decommit[4][SHA256_DIGEST_LENGTH], int id, bool inputs[INPUT_4M])
{
	memcpy(buffer1, inputs, INPUT_4M);
	switch(id)
	{
		case 0: commitInputs(my_Commit[1],buffer1, IINPUT_FIRST_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				commitInputs(my_Commit[2],buffer1 + IINPUT_FIRST_SHARE_, INPUT_PER_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				commitInputs(my_Commit[3],buffer1 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, INPUT_PER_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				//commitInputs(my_Commit[0],buffer1, IINPUT_FIRST_SHARE_, NULL, COMMIT_SCHEME_SHA256);

				memcpy(&my_Decommit[1][0], buffer1, IINPUT_FIRST_SHARE_);
				memcpy(&my_Decommit[2][0], buffer1 + IINPUT_FIRST_SHARE_, INPUT_PER_SHARE_);
				memcpy(&my_Decommit[3][0], buffer1 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, INPUT_PER_SHARE_);

				//send code

				break;

		case 1: commitInputs(my_Commit[0],buffer1 + INPUT_4M/4, IINPUT_FIRST_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				commitInputs(my_Commit[2],buffer1 + INPUT_4M/4 + IINPUT_FIRST_SHARE_, INPUT_PER_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				commitInputs(my_Commit[3],buffer1 + INPUT_4M/4 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, INPUT_PER_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				//commitInputs(my_Commit[0],buffer1, IINPUT_FIRST_SHARE_, NULL, COMMIT_SCHEME_SHA256);

				memcpy(&my_Decommit[0][0], buffer1 + INPUT_4M/4, IINPUT_FIRST_SHARE_);
				memcpy(&my_Decommit[2][0], buffer1 + INPUT_4M/4 + IINPUT_FIRST_SHARE_, INPUT_PER_SHARE_);
				memcpy(&my_Decommit[3][0], buffer1 + INPUT_4M/4 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, INPUT_PER_SHARE_);

				//send code

				break;

		case 2: commitInputs(my_Commit[0],buffer1 + INPUT_4M/2, IINPUT_FIRST_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				commitInputs(my_Commit[1],buffer1 + INPUT_4M/2 + IINPUT_FIRST_SHARE_, INPUT_PER_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				commitInputs(my_Commit[3],buffer1 + INPUT_4M/2 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, INPUT_PER_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				//commitInputs(my_Commit[0],buffer1, IINPUT_FIRST_SHARE_, NULL, COMMIT_SCHEME_SHA256);

				memcpy(&my_Decommit[0][0], buffer1 + INPUT_4M/2, IINPUT_FIRST_SHARE_);
				memcpy(&my_Decommit[1][0], buffer1 + INPUT_4M/2 + IINPUT_FIRST_SHARE_, INPUT_PER_SHARE_);
				memcpy(&my_Decommit[3][0], buffer1 + INPUT_4M/2 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, INPUT_PER_SHARE_);

				//send code

				break;


		case 3: commitInputs(my_Commit[0],buffer1 + 3 * INPUT_4M/4, IINPUT_FIRST_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				commitInputs(my_Commit[1],buffer1 + 3 * INPUT_4M/4 + IINPUT_FIRST_SHARE_, INPUT_PER_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				commitInputs(my_Commit[2],buffer1 + 3 * INPUT_4M/4 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, INPUT_PER_SHARE_, NULL, COMMIT_SCHEME_SHA256);
				//commitInputs(my_Commit[0],buffer1, IINPUT_FIRST_SHARE_, NULL, COMMIT_SCHEME_SHA256);

				memcpy(&my_Decommit[0][0], buffer1 + 3 * INPUT_4M/4, IINPUT_FIRST_SHARE_);
				memcpy(&my_Decommit[1][0], buffer1 + 3 * INPUT_4M/4 + IINPUT_FIRST_SHARE_, INPUT_PER_SHARE_);
				memcpy(&my_Decommit[2][0], buffer1 + 3 * INPUT_4M/4 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, INPUT_PER_SHARE_);

				//send code

				break;
	}

}

//send openings
void sendOpenings(unsigned char my_Commit[3][SHA256_DIGEST_LENGTH], unsigned char my_Decommit[3][SHA256_DIGEST_LENGTH], int id)
{
	switch(id)
	{
		case 0:	memcpy( buffer1, my_Decommit[1],IINPUT_FIRST_SHARE_);
				//send code
				memcpy( buffer1 + IINPUT_FIRST_SHARE_, my_Decommit[2], INPUT_PER_SHARE_);
				//send code
				memcpy( buffer1 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, my_Decommit[3], INPUT_PER_SHARE_);
				//send code


				break;

		case 1: memcpy( buffer1 + INPUT_4M/4, my_Decommit[0], IINPUT_FIRST_SHARE_);
				//send code
				memcpy( buffer1 + INPUT_4M/4 + IINPUT_FIRST_SHARE_, my_Decommit[2], INPUT_PER_SHARE_);
				//send code
				memcpy( buffer1 + INPUT_4M/4 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, my_Decommit[3], INPUT_PER_SHARE_);

				//send code

				break;

		case 2: memcpy( buffer1 + INPUT_4M/2, my_Decommit[0], IINPUT_FIRST_SHARE_);
				//send code
				memcpy( buffer1 + INPUT_4M/2 + IINPUT_FIRST_SHARE_, my_Decommit[1], INPUT_PER_SHARE_);
				//send code
				memcpy( buffer1 + INPUT_4M/2 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, my_Decommit[3], INPUT_PER_SHARE_);

				//send code

				break;


		case 3: memcpy( buffer1 + 3 * INPUT_4M/4, my_Decommit[0], IINPUT_FIRST_SHARE_);
				//send code
				memcpy( buffer1 + 3 * INPUT_4M/4 + IINPUT_FIRST_SHARE_, my_Decommit[1], INPUT_PER_SHARE_);
				//send code
				memcpy( buffer1 + 3 * INPUT_4M/4 + IINPUT_FIRST_SHARE_ + INPUT_PER_SHARE_, my_Decommit[2], INPUT_PER_SHARE_);

				//send code

				break;
	}
}


void recvOpenings(unsigned char recvd_commitment[4][4][SHA256_DIGEST_LENGTH], unsigned char recvd_open[4][4][SHA256_DIGEST_LENGTH], int id, int fromid)
{




	//recv code

	memcpy(&recvd_open[fromid][TS[fromid][id][0]], buffer1, INPUT_PER_SHARE_);
	memcpy(&recvd_open[fromid][TS[fromid][id][1]], buffer1 + INPUT_PER_SHARE_, INPUT_PER_SHARE_);

	verifyRecvdCom(&recvd_commitment[fromid][TS[fromid][id][0]][0], recvd_open[fromid][TS[fromid][id][0]], INPUT_PER_SHARE_, id, fromid);
	verifyRecvdCom(&recvd_commitment[fromid][TS[fromid][id][1]][0], recvd_open[fromid][TS[fromid][id][1]], INPUT_PER_SHARE_, id, fromid);

	/*switch(id)
	{
		case 0: memcpy(&recvd_open[fromid][T[fromid][id][0]], buffer1, sizeof(block));
				memcpy(&recvd_open[fromid][T[fromid][id][1]], buffer1 + sizeof(block), sizeof(block));

				break;

		case 1: memcpy(&recvd_open[fromid][T[fromid][id][0]], buffer1, sizeof(block));
				memcpy(&recvd_open[fromid][T[fromid][id][1]], buffer1 + sizeof(block), sizeof(block));

				break;

		case 2: memcpy(&recvd_open[fromid][T[fromid][id][0]], buffer1, sizeof(block));
				memcpy(&recvd_open[fromid][T[fromid][id][1]], buffer1 + sizeof(block), sizeof(block));

				break;

		case 3: memcpy(&recvd_open[fromid][T[fromid][id][0]], buffer1, sizeof(block));
				memcpy(&recvd_open[fromid][T[fromid][id][1]], buffer1 + sizeof(block), sizeof(block));

				break;

	}*/

}





//verify commitments received
void verifyRecvdCom(unsigned char * out2, unsigned char * msg, int size, int id, int fromid)
{
	if(verify_commitInputs(out2, msg, size, NULL, COMMIT_SCHEME_SHA256) == false)
	{
		printf("Commitment received from party %d not verified\n", fromid );
		corrupt_set_[id].insert(fromid);
	}

}




void recvCommitments(unsigned char recvd_commitment[4][4][SHA256_DIGEST_LENGTH], int id, int fromid)
{
	//recv code

	switch(id)
	{
		case 0: memcpy(&recvd_commitment[fromid][((((fromid-1) < 0) ? (((fromid-1) % 4) + 4) : (fromid - 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitment[fromid][((((fromid+1) < 0) ? (((fromid+1) % 4) + 4) : (fromid + 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitment[fromid][((((fromid+2) < 0) ? (((fromid+2) % 4) + 4) : (fromid + 2)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);

				break;

		case 1: memcpy(&recvd_commitment[fromid][((((fromid-1) < 0) ? (((fromid-1) % 4) + 4) : (fromid - 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitment[fromid][((((fromid+1) < 0) ? (((fromid+1) % 4) + 4) : (fromid + 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitment[fromid][((((fromid+2) < 0) ? (((fromid+2) % 4) + 4) : (fromid + 2)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);

				break;

		case 2: memcpy(&recvd_commitment[fromid][((((fromid-1) < 0) ? (((fromid-1) % 4) + 4) : (fromid - 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitment[fromid][((((fromid+1) < 0) ? (((fromid+1) % 4) + 4) : (fromid + 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitment[fromid][((((fromid+2) < 0) ? (((fromid+2) % 4) + 4) : (fromid + 2)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);

				break;

		case 3: memcpy(&recvd_commitment[fromid][((((fromid-1) < 0) ? (((fromid-1) % 4) + 4) : (fromid - 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitment[fromid][((((fromid+1) < 0) ? (((fromid+1) % 4) + 4) : (fromid + 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitment[fromid][((((fromid+2) < 0) ? (((fromid+2) % 4) + 4) : (fromid + 2)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);

				break;
	}


}





//exchange commitments and relevant openings
void sendComR2(unsigned char recvd_commitment[4][4][SHA256_DIGEST_LENGTH], int id)
{
	memcpy(buffer1, recvd_commitment, 4 * 4 * COMMIT_SCHEME_SHA256);
	//send code

	/*switch(id)
	{
		case 0: memcpy(buffer1, recvd_commitment, 4 * 4 * COMMIT_SCHEME_SHA256);
				memcpy(buffer1 + 4 * COMMIT_SCHEME_SHA256, recvd_commitment[2], 4 * COMMIT_SCHEME_SHA256);
				memcpy(buffer1 + 8 * COMMIT_SCHEME_SHA256, recvd_commitment[3], 4 * COMMIT_SCHEME_SHA256);

				break;

		case 1: memcpy(buffer1, recvd_commitment[], 3 * COMMIT_SCHEME_SHA256);
				memcpy(buffer1 + 3 * COMMIT_SCHEME_SHA256, recvd_commitment[2], 3 * COMMIT_SCHEME_SHA256);
				memcpy(buffer1 + 6 * COMMIT_SCHEME_SHA256, recvd_commitment[3], 3 * COMMIT_SCHEME_SHA256);

				break;

		case 2:

		case 3:
	}*/

}

void sendOpenR2(unsigned char recvd_open[4][4][SHA256_DIGEST_LENGTH], int id, int toid)
{
	int i1 = TS[id][toid][0];
	int i2 = TS[id][toid][1];
	memcpy(buffer1, &recvd_open[i1][TS[id][i1][0]],  INPUT_PER_SHARE_);
	memcpy(buffer1 +  sizeof(block), &recvd_open[i2][TS[id][i2][0]],  INPUT_PER_SHARE_);
	//send code

}

void recvCommitmentsR2(unsigned char recvd_commitmentR2[4][4][4][SHA256_DIGEST_LENGTH], int id, int fromid)
{
	//recv code


	memcpy(recvd_commitmentR2[fromid], buffer1, 4*4*COMMIT_SCHEME_SHA256);

	/*switch(id)
	{
		case 0: memcpy(&recvd_commitmentR2[fromid][((((fromid-1) < 0) ? (((fromid-1) % 4) + 4) : (fromid - 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitmentR2[fromid][((((fromid+1) < 0) ? (((fromid+1) % 4) + 4) : (fromid + 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitmentR2[fromid][((((fromid+2) < 0) ? (((fromid+2) % 4) + 4) : (fromid + 2)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);

				break;

		case 1: memcpy(&recvd_commitmentR2[fromid][((((fromid-1) < 0) ? (((fromid-1) % 4) + 4) : (fromid - 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitmentR2[fromid][((((fromid+1) < 0) ? (((fromid+1) % 4) + 4) : (fromid + 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitmentR2[fromid][((((fromid+2) < 0) ? (((fromid+2) % 4) + 4) : (fromid + 2)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);

				break;

		case 2: memcpy(&recvd_commitmentR2[fromid][((((fromid-1) < 0) ? (((fromid-1) % 4) + 4) : (fromid - 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitmentR2[fromid][((((fromid+1) < 0) ? (((fromid+1) % 4) + 4) : (fromid + 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitmentR2[fromid][((((fromid+2) < 0) ? (((fromid+2) % 4) + 4) : (fromid + 2)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);

				break;

		case 3: memcpy(&recvd_commitmentR2[fromid][((((fromid-1) < 0) ? (((fromid-1) % 4) + 4) : (fromid - 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitmentR2[fromid][((((fromid+1) < 0) ? (((fromid+1) % 4) + 4) : (fromid + 1)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);
				memcpy(&recvd_commitmentR2[fromid][((((fromid+2) < 0) ? (((fromid+2) % 4) + 4) : (fromid + 2)) % 4)][0], buffer1, COMMIT_SCHEME_SHA256);

				break;
	}*/


}


void recvOpeningsR2(unsigned char recvd_openR2[4][4][SHA256_DIGEST_LENGTH], int id, int fromid, int toid)
{
	int i1 = TS[id][fromid][0];
	int i2 = TS[id][toid][1];
	//recv code

	memcpy(&recvd_openR2[i1][TS[i1][id][0]], buffer1, INPUT_PER_SHARE_);
	memcpy(&recvd_openR2[i2][TS[i2][id][0]], buffer1 + INPUT_PER_SHARE_, INPUT_PER_SHARE_);

}

//select majority
void chooseMajority(unsigned char recvd_commitment[4][4][SHA256_DIGEST_LENGTH], unsigned char recvd_commitmentR2[4][4][4][SHA256_DIGEST_LENGTH], unsigned char commit_majority_[4][4][SHA256_DIGEST_LENGTH], unsigned char open_majority_[4][4][SHA256_DIGEST_LENGTH], int id)
{
	int  * arr = arrP_[id];
	unsigned char * c1, *c2, *c3;


	for (int j = 0; j < 3; ++j)
	{
		int *subarr = arrP_[arr[j]];

		for (int i = 0; i < 3; ++i)
		{
			c1 = recvd_commitment[arr[j]][subarr[i]];
			c2 = recvd_commitmentR2[arr[(j+1)%4]][arr[j]][subarr[i]];
			c3 = recvd_commitmentR2[arr[(j+2)%4]][arr[j]][subarr[i]];

			if(memcmp(c1,c2,SHA256_DIGEST_LENGTH) == 0 && memcmp(c1,c3, SHA256_DIGEST_LENGTH) == 0 && memcmp(c2,c3, SHA256_DIGEST_LENGTH)==0)
			{
				memcpy(commit_majority_[arr[j]][subarr[i]],c1,SHA256_DIGEST_LENGTH);

			}
			else if(memcmp(c1,c2,SHA256_DIGEST_LENGTH) == 0 && memcmp(c1,c3, SHA256_DIGEST_LENGTH) != 0 && memcmp(c2,c3, SHA256_DIGEST_LENGTH)!=0)
			{
				//commit_majority_[arr[j]][subarr[i]]= c1;
				memcpy(commit_majority_[arr[j]][subarr[i]],c1,SHA256_DIGEST_LENGTH);
			}
			else if(memcmp(c1,c2,SHA256_DIGEST_LENGTH) != 0 && memcmp(c1,c3, SHA256_DIGEST_LENGTH) != 0 && memcmp(c2,c3, SHA256_DIGEST_LENGTH)==0)
			{
				//commit_majority_[arr[j]][subarr[i]]= c2;
				memcpy(commit_majority_[arr[j]][subarr[i]],c2,SHA256_DIGEST_LENGTH);
			}
			else if(memcmp(c1,c2,SHA256_DIGEST_LENGTH) != 0 && memcmp(c1,c3, SHA256_DIGEST_LENGTH) == 0 && memcmp(c2,c3, SHA256_DIGEST_LENGTH)!=0)
			{
				//commit_majority_[arr[j]][subarr[i]]= c1;
				memcpy(commit_majority_[arr[j]][subarr[i]],c1,SHA256_DIGEST_LENGTH);
			}
			else
			{
				memset(commit_majority_[arr[j]][subarr[i]], 0, SHA256_DIGEST_LENGTH);
			}

		}

	}
}


void chooseMajorityOpen(unsigned char recvd_open[4][4][SHA256_DIGEST_LENGTH], unsigned char recvd_openR2[4][4][SHA256_DIGEST_LENGTH], unsigned char commit_majority_[4][4][SHA256_DIGEST_LENGTH], unsigned char open_majority_[4][4][SHA256_DIGEST_LENGTH], int id)
{
	int  * arr = arrP_[id];
	unsigned char * c1, *c2, *c3;



	for (int k = 0; k < 3; ++k)
	{
		int *subarr = arrP_[arr[k]];

		for (int i = 0; i < 3; ++i)
		{
			for (int j = 0; j < 2; ++j)
			{

				c1 = recvd_open[arr[i]][TS[id][arr[i]][j]];
				c2 = recvd_openR2[arr[i]][TS[id][arr[i]][j]];
				c3 = commit_majority_[arr[i]][TS[id][arr[i]][j]];

				if(verify_commitInputs(c3,c1, INPUT_PER_SHARE_,NULL, COMMIT_SCHEME_SHA256)== false)
				{
					if(verify_commitInputs(c3,c2, INPUT_PER_SHARE_,NULL, COMMIT_SCHEME_SHA256)== false){
						memset(open_majority_[arr[i]][TS[id][arr[i]][j]], 0, SHA256_DIGEST_LENGTH);

					}
					else{
						memcpy(open_majority_[arr[i]][TS[id][arr[i]][j]], c2, INPUT_PER_SHARE_);
					}
				}
				else
				{
					//open_majority_[arr[i]][T[id][arr[i]][j]] = c1;
					memcpy(open_majority_[arr[i]][TS[id][arr[i]][j]], c1, INPUT_PER_SHARE_);
				}
			}
		}
	}

}
