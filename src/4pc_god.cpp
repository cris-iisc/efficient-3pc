#include "../primitives/primitives.h"
#include "../primitives/socket.h"
#include "../primitives/setup.h"

// p0 - garbler 1 ip[0]
// p1 - garbler 2
// p2 - evaluator 1
// p3 - evaluator 2
// ip of 4 computers in the lan
char *ip[4]= {"127.0.0.1","127.0.0.1","127.0.0.1","127.0.0.1"};
int addr_soc[4];  // socket address for other parties
int id; //0-P0, 1-P1, 2-P2, 3-P3

//varies from circuit to circuits
#define INPUT_4M 256
int blocks_in_one_round = MAX_PAYLOAD_SIZE/sizeof(block);
int sha256_in_one_round = blocks_in_one_round/2;

// #define GC_FILE "circuits/sha_256.txt"
#define GC_FILE "circuits/aes.txt"
// #define DEBUG

//time calculations
#define CLOCKS_PER_M_SEC 1000
double comp_time = 0, network_time = 0;
double wait_time = 0;

//network bytes
double send_bytes = 0, recv_bytes = 0, broadcast_bytes = 0;

int T[4][4][2] ={
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

int INPUT_PER_SHARE = INPUT_4M/12;
int INPUT_FIRST_SHARE = INPUT_4M/4 - 2 * INPUT_PER_SHARE;

//Mutex variables for thread syncronization
mutex round_mtx[4][4][4];
mutex garble_done_mtx;
mutex eval_complete;
mutex comp_time_mtx;

//Global variables used by both threads
garble_circuit gc;
void* commit_ip[4];
void* gc_hashh[4];
block *inputLabels;
block *outputMap;

bool b[2*INPUT_4M];
bool inputs[INPUT_4M];
bool decomm[INPUT_4M];
bool decom[INPUT_4M];
block *extractedLabels;
block *extractedLabels0;
block *extractedLabels1;
block *computedOutputMap;
bool *outputVals;
u_char b_array[INPUT_4M/8];//INPUT_4M/8 for efficiency
block seed;

char commit_msg[400000*2][SHA256_DIGEST_LENGTH];
u_char hashh[SHA256_DIGEST_LENGTH];
u_char hashh1[SHA256_DIGEST_LENGTH];

unsigned char commit_majority[4][4][SHA256_DIGEST_LENGTH];
unsigned char open_majority[4][4][SHA256_DIGEST_LENGTH];

unsigned char recvd_commitment[4][4][SHA256_DIGEST_LENGTH]; //4 parties, each has 3 commitments, each commitment is 256bits
unsigned char recvd_commitmentR2[4][4][4][SHA256_DIGEST_LENGTH]; //4 parties, each has 3 commitments, each commitment is 256bits
unsigned char recvd_open[4][4][SHA256_DIGEST_LENGTH]; //4 parties each has two shares
unsigned char recvd_openR2[4][4][SHA256_DIGEST_LENGTH]; //4 parties each has two shares

unsigned char my_Commit[4][SHA256_DIGEST_LENGTH]; //gen commitment for 3 shares
unsigned char my_Decommit[4][SHA256_DIGEST_LENGTH]; //decommitment for 3 shares

void send_input_commits(int to_id){
  u_char buffer[MAX_PAYLOAD_SIZE];

  memcpy(buffer, my_Commit, 4*SHA256_DIGEST_LENGTH);
  memcpy(buffer+4*SHA256_DIGEST_LENGTH, my_Decommit[T[id][to_id][0]], INPUT_FIRST_SHARE);
  memcpy(buffer+4*SHA256_DIGEST_LENGTH+INPUT_FIRST_SHARE, my_Decommit[T[id][to_id][1]], INPUT_FIRST_SHARE);

  send(addr_soc[to_id],buffer,4*SHA256_DIGEST_LENGTH+2*INPUT_FIRST_SHARE,0);
}

void recv_input_commits(int from_id){
  u_char buffer[MAX_PAYLOAD_SIZE];

  recv(addr_soc[from_id],buffer,4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE,0);

  memcpy(recvd_commitment[from_id], buffer, 4 * SHA256_DIGEST_LENGTH);
  memcpy(recvd_open[from_id][T[from_id][id][0]], buffer + 4 * SHA256_DIGEST_LENGTH, INPUT_FIRST_SHARE);
  memcpy(recvd_open[from_id][T[from_id][id][1]], buffer + 4 * SHA256_DIGEST_LENGTH+ INPUT_FIRST_SHARE, INPUT_FIRST_SHARE);
}

void send_input_commits_r2(int to_id){
  u_char buffer[MAX_PAYLOAD_SIZE];
  memcpy(buffer, recvd_commitment, 4 * 4 * SHA256_DIGEST_LENGTH);
  memcpy(buffer+4*4*SHA256_DIGEST_LENGTH, recvd_open[T[to_id][id][1]][T[to_id][id][0]], INPUT_FIRST_SHARE);
  send(addr_soc[to_id],buffer,4*4*SHA256_DIGEST_LENGTH+INPUT_FIRST_SHARE,0);
}

void recv_input_commits_r2(int from_id){
  u_char buffer[MAX_PAYLOAD_SIZE];
  recv(addr_soc[from_id],buffer,4*4*SHA256_DIGEST_LENGTH+INPUT_FIRST_SHARE,0);
  memcpy(recvd_commitmentR2[from_id], buffer, 4 * 4 * SHA256_DIGEST_LENGTH);
  memcpy(recvd_openR2[from_id][from_id], buffer, INPUT_FIRST_SHARE);

  if(memcmp(recvd_commitmentR2[from_id],recvd_commitment,16*SHA256_DIGEST_LENGTH)!=0){
    cout<<"commitment round 2 is not equal\n";
    //choose majority
    chooseMajority(recvd_commitment, recvd_commitmentR2, commit_majority, open_majority, 1);
  }
}

void construct_inputs_from_openings(){
  //Regenerating inputs ----------------------------------
  //copying all inputs to inputs variable for extracting labels
  for(int i=0;i<4;++i){//i0 to 3 for all 3 parties
    int j=0, offset = 0,first_share = 0;
    if(i==id) ++i;
    while(j<4){
      if(i==j) {j++;continue;}
      if(first_share == 0){
        memcpy(inputs+i*(INPUT_4M/4)+offset,recvd_open[i][j],INPUT_FIRST_SHARE);
        offset+=INPUT_FIRST_SHARE;
        first_share = 1;
      }
      else{
        memcpy(inputs+i*INPUT_4M/4+offset,recvd_open[i][j],INPUT_PER_SHARE);
        offset+=INPUT_PER_SHARE;
      }
      j++;
    }
  }

  #ifdef DEBUG
    // for(int i = 0;i<INPUT_4M;i++){
    // 	cout<<i<<" "<<inputs[i]<<"\n";
    // }
  #endif
}

void combine_extractedLabels(){
  extractedLabels = garble_allocate_blocks(gc.n);
  memcpy(extractedLabels,extractedLabels0,gc.n*sizeof(block));
  memcpy(extractedLabels+gc.n/4,extractedLabels1+gc.n/4,INPUT_FIRST_SHARE*sizeof(block));
  memcpy(extractedLabels+gc.n/2,extractedLabels1+gc.n/2,INPUT_FIRST_SHARE*sizeof(block));
  memcpy(extractedLabels+gc.n/2+gc.n/4,extractedLabels1+gc.n/2+gc.n/4,INPUT_FIRST_SHARE*sizeof(block));
}
//communication
// Garbler 1 talks to Garbler 2 and vice versa
int p0_p1_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];
  clock_t time_beg, time_end;
  if(id == 0){//Garbler 1's side
    //generating randomness
    randomGen(b_array,INPUT_4M/8);
    seed = garble_seed(NULL);

        //dummy send (for exact timing calculations)
        send(addr_soc[1],buffer,1,0);
        time_beg = clock();
      send_input_commits(1);
        time_end = clock();
        network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
        send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

      recv(addr_soc[1],buffer,1,0);
      time_beg = clock();
    recv_input_commits(1);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes+= 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

    memcpy(recvd_commitment[id], my_Commit, 4 * SHA256_DIGEST_LENGTH);

    //Sampling b===========================================================
    //random b values for commitment
    for(int i=0;i<INPUT_4M/8;++i){
      for(int j=0;j<8;++j){
        b[i*8+j] = (b_array[i]>>j)& 1;
      }
    }
  	// Sampled b------------------------------------------------------------

    time_beg = clock();//computation time
    //verify commitments
    verifyRecvdCom(recvd_commitment[1][T[1][id][1]], recvd_open[1][T[1][id][1]], INPUT_PER_SHARE, 0, 1);
    verifyRecvdCom(recvd_commitment[1][T[1][id][0]], recvd_open[1][T[1][id][0]], INPUT_PER_SHARE, 0, 1);
    time_end = clock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

      //dummy send (for exact timing calculations)
      send(addr_soc[1],buffer,1,0);
      time_beg = clock();
    //sharing randomness
    memcpy(buffer,&seed,sizeof(block));
    memcpy(buffer+sizeof(block),b_array,INPUT_4M/8);
    send(addr_soc[1],buffer,INPUT_4M/8+sizeof(block),0);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += INPUT_4M/8+sizeof(block);

    //P0_P1_R0 completed
    round_mtx[0][1][0].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[0][2][0].lock();
    round_mtx[0][2][0].unlock();
    round_mtx[0][3][0].lock();
    round_mtx[0][3][0].unlock();
    printf("\n*****\nRound one is complete ...\n******\n\n");

    //Round 2===============================================================================

    //dummy send (for exact timing calculations)
      send(addr_soc[1],buffer,1,0);
      time_beg = clock();
    send_input_commits_r2(1);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*4*SHA256_DIGEST_LENGTH+INPUT_FIRST_SHARE;

  		recv(addr_soc[1],buffer,1,0);
  		time_beg = clock();
  	recv_input_commits_r2(1);
  		time_end = clock();
  		network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
  		recv_bytes+= 4*4*SHA256_DIGEST_LENGTH+INPUT_FIRST_SHARE;

      time_beg = clock();//computation time
    //Garbling==============================================================
    inputLabels = garble_allocate_blocks(2 * gc.n);
    outputMap = garble_allocate_blocks(2 * gc.m);
    extractedLabels = garble_allocate_blocks(gc.n);

    if (garble_garble(&gc, NULL, outputMap) == GARBLE_ERR) {
        fprintf(stderr, "garble failed\n");
        return -1;
    }
    #ifdef DEBUG
      // printf("Garbled gates\n");
    #endif
    //Garbled----------------------------------------------------------------

    garble_hash(&gc, hashh1);
    #ifdef DEBUG
      // printf("hashh Computed\n");
      // printf("%s\n", hashh1);
    #endif

    //Committing on 4m labels====================================================
    int i=0;
    while(i<gc.n){
        commit(&(commit_msg[2*i][0]),gc.wires[2*i+b[i]],NULL, COMMIT_SCHEME_SHA256);
        commit(&(commit_msg[2*i+1][0]),gc.wires[2*i+1-b[i]],NULL, COMMIT_SCHEME_SHA256);
        ++i;
    }
    #ifdef DEBUG
      // printf("Committed to wires\n");
      // for(i=0;i<5;i++)
      //   printf("%d :%s\n",i,commit_msg[i]);
    #endif
    //Committed to 4m wire labels-------------------------------------------------

    //decom info
    for (int i = 0; i < INPUT_4M; ++i){
        decom[i] = (inputs[i] + b[i]) % 2;
    }

    construct_inputs_from_openings();//reconstructing inputs
    memcpy(inputLabels, gc.wires, 2 * gc.n * sizeof(block));
    garble_extract_labels1(extractedLabels, inputLabels, inputs, gc.n);

      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    garble_done_mtx.unlock();

    //P0_P1_R1 completed
    round_mtx[0][1][1].unlock();
    //Waiting for other threds to complete round 0(1)
    round_mtx[0][2][1].lock();
    round_mtx[0][2][1].unlock();
    round_mtx[0][3][1].lock();
    round_mtx[0][3][1].unlock();

  }
  else if(id == 1){// Garbler 2's side

      //dummy send (for exact timing calculations)
      recv(addr_soc[0],buffer,1,0);
      time_beg = clock();
    recv_input_commits(0);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes+= 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

      //dummy send (for timing calculations)
      send(addr_soc[0],buffer,1,0);
      time_beg = clock();
    send_input_commits(0);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

    //receive randomness
      //dummy send (for exact timing calculations)
      recv(addr_soc[0],buffer,1,0);
      time_beg = clock();
    recv(addr_soc[0],buffer,INPUT_4M/8+sizeof(block),0);
    memcpy(&seed,buffer,sizeof(block));
    memcpy(b_array,buffer+sizeof(block),INPUT_4M/8);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes+= INPUT_4M/8+sizeof(block);

      time_beg = clock();//computation time

    memcpy(recvd_commitment[id], my_Commit, 4 * SHA256_DIGEST_LENGTH);

    //verify commitments
    verifyRecvdCom(recvd_commitment[0][T[0][id][0]], recvd_open[0][T[0][id][0]], INPUT_PER_SHARE, 1, 0);
    verifyRecvdCom(recvd_commitment[0][T[0][id][0]], recvd_open[0][T[0][id][0]], INPUT_PER_SHARE, 1, 0);

    seed = garble_seed(&seed);

    //Sampling b===========================================================
    //random b values for commitment
    for(int i=0;i<INPUT_4M/8;++i){
      for(int j=0;j<8;++j){
        b[i*8+j] = (b_array[i]>>j)& 1;
      }
    }
    // Sampled b------------------------------------------------------------
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    //P0_P1_R0 completed
    round_mtx[0][1][0].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[1][2][0].lock();
    round_mtx[1][2][0].unlock();
    round_mtx[1][3][0].lock();
    round_mtx[1][3][0].unlock();

    printf("\n*****\nRound one is complete ...\n******\n");

    //Round 2 ============================================================================
      //dummy send (for exact timing calculations)
      recv(addr_soc[0],buffer,1,0);
      time_beg = clock();
    recv_input_commits_r2(0);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes+= 4*4*SHA256_DIGEST_LENGTH+INPUT_FIRST_SHARE;

  		send(addr_soc[0],buffer,1,0);
  		time_beg = clock();
    send_input_commits_r2(0);
  		time_end = clock();
  		network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
  		send_bytes += 4*4*SHA256_DIGEST_LENGTH+INPUT_FIRST_SHARE;

      time_beg = clock();//computation time

    //Garbling==============================================================
    inputLabels = garble_allocate_blocks(2 * gc.n);
    outputMap = garble_allocate_blocks(2 * gc.m);
    extractedLabels = garble_allocate_blocks(gc.n);

    if (garble_garble(&gc, NULL, outputMap) == GARBLE_ERR) {
        fprintf(stderr, "garble failed\n");
        return -1;
    }
    #ifdef DEBUG
      printf("Garbled gates\n");
    #endif
    //Garbled----------------------------------------------------------------

    memcpy(inputLabels, gc.wires, 2 * gc.n * sizeof(block));

    garble_hash(&gc, hashh1);
    #ifdef DEBUG
      printf("hashh Computed\n");
      printf("%s\n", hashh1);
    #endif


    //Committing on 4m labels====================================================
    int i=0;
    while(i<gc.n){
        commit(&(commit_msg[2*i][0]),gc.wires[2*i+b[i]],NULL, COMMIT_SCHEME_SHA256);
        commit(&(commit_msg[2*i+1][0]),gc.wires[2*i+1-b[i]],NULL, COMMIT_SCHEME_SHA256);
        ++i;
    }
    #ifdef DEBUG
      printf("Committed to wires\n");
      // for(i=0;i<5;i++)
      //   printf("%d :%s\n",i,commit_msg[i]);
    #endif
    //Committed to 4m wire labels-------------------------------------------------

    //decom info
    for (int i = 0; i < INPUT_4M; ++i){
        decom[i] = (inputs[i] + b[i]) % 2;
    }
    construct_inputs_from_openings();//reconstructing inputs
    garble_extract_labels1(extractedLabels, inputLabels, inputs, gc.n);
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    garble_done_mtx.unlock();

    //P0_P1_R1 completed
    round_mtx[0][1][1].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[1][2][1].lock();
    round_mtx[1][2][1].unlock();
    round_mtx[1][3][1].lock();
    round_mtx[1][3][1].unlock();

  }//if id = 1
}

// Garbler 1 v/s Evaluator 1
int p0_p2_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];
  int i,j;
  clock_t time_beg, time_end;

  if(id == 0){ //id 0 if
  	  recv(addr_soc[2],buffer,1,0);
  	  time_beg = clock();
    recv_input_commits(2);
    send_input_commits(2);
  	  time_end = clock();
  	  network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
  	  send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;
  	  recv_bytes+= 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

      time_beg = clock();//computation time
    //verify commitments
    verifyRecvdCom(recvd_commitment[2][T[2][0][0]], recvd_open[2][T[2][0][0]], INPUT_PER_SHARE, 0, 2);
    verifyRecvdCom(recvd_commitment[2][T[2][0][1]], recvd_open[2][T[2][0][1]], INPUT_PER_SHARE, 0, 2);
      time_end = clock();
  		comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;


    //P0_P2_R0 completed
    round_mtx[0][2][0].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[0][1][0].lock();
    round_mtx[0][1][0].unlock();
    round_mtx[0][3][0].lock();
    round_mtx[0][3][0].unlock();

    //Round 2===============================================================================
  		send(addr_soc[2],buffer,1,0);
  		time_beg = clock();
    send_input_commits_r2(2);
    recv_input_commits_r2(2);
  		time_end = clock();
  		network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
  		send_bytes += 4*4*SHA256_DIGEST_LENGTH;
  		recv_bytes+= 4*4*SHA256_DIGEST_LENGTH;

    garble_done_mtx.lock();
    garble_done_mtx.unlock();
    //Sending Cs==================================================================
    //sending comitments for input wires.
    int no_of_rounds = (gc.n*2/sha256_in_one_round);
    int blocks_in_last_round = gc.n*2 %blocks_in_one_round;
    #ifdef DEBUG
      printf("Sending commitments...\n");
      // printf("no of rounds = %d ; blk_in lst_round %d\n",no_of_rounds,blocks_in_last_round);
    #endif

      //dummy send (for exact timing calculations)
      send(addr_soc[2],buffer,1,0);
      time_beg = clock();

    //Sending b values of Evaluator 1===============================================
    memcpy(buffer, b,sizeof(bool)*INPUT_4M);
    send(addr_soc[2],buffer,sizeof(bool)*INPUT_4M,0);
    //Sent b values to the evaluator----------------------------------------------

    for(j=0;j< no_of_rounds;++j){
        memcpy(buffer,&commit_msg[j*sha256_in_one_round],sha256_in_one_round*SHA256_DIGEST_LENGTH);
        send(addr_soc[2],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
    }//sending last round
    memcpy(buffer,&commit_msg[j*sha256_in_one_round],blocks_in_last_round*SHA256_DIGEST_LENGTH);
    send(addr_soc[2],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);
    //Sent Cs----------------------------------------------------------------------

    //Sending GC===================================================================
    int size_of_table = (gc.q - gc.nxors);
    no_of_rounds = (2*size_of_table/blocks_in_one_round);
    blocks_in_last_round = (2*size_of_table) %blocks_in_one_round;

    #ifdef DEBUG
      printf("Sending GC...\n");
      // printf("no of rounds = %d ;blocks in last round= %d\n",no_of_rounds,blocks_in_last_round);
    #endif

    for(j=0;j<no_of_rounds;++j){
      memcpy(buffer,gc.table+j*blocks_in_one_round,blocks_in_one_round*sizeof(block));
      send(addr_soc[2],buffer,blocks_in_one_round*sizeof(block),0);
    }
    memcpy(buffer,gc.table+j*blocks_in_one_round,blocks_in_last_round*sizeof(block));
    send(addr_soc[2],buffer,blocks_in_last_round*sizeof(block),0);

    //send output_perms
    memcpy(buffer,gc.output_perms,sizeof(bool)*gc.m);
    send(addr_soc[2],buffer,sizeof(bool)*gc.m,0);
    //Sent GC-----------------------------------------------------------------------

    //Send Decommitments============================================================
    #ifdef DEBUG
    printf("Senting Decomitment info!\n");
    #endif

    //Garbler's index of decommitment
    memcpy(buffer,decom, sizeof(bool) * INPUT_4M);
    send(addr_soc[2], buffer, sizeof(bool) * INPUT_4M, 0);
    //Sent Decommitments-------------------------------------------------------------
    //Garblers labels for decommit
    memcpy(buffer,extractedLabels,sizeof(block) * gc.n);
    send(addr_soc[2],buffer,sizeof(block) * gc.n,0);

      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += gc.n*2*SHA256_DIGEST_LENGTH+2*size_of_table*sizeof(block)+gc.m+INPUT_4M+ INPUT_4M+sizeof(block)*gc.n;

    //P0_P2_R1 completed
    round_mtx[0][2][1].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[0][1][1].lock();
    round_mtx[0][1][1].unlock();
    round_mtx[0][3][1].lock();
    round_mtx[0][3][1].unlock();

    //Round 3=======================================================================
          time_beg = clock();//computation time
    computedOutputMap = garble_allocate_blocks(gc.m);
    outputVals = (bool*) calloc(gc.m, sizeof(bool));
          time_end = clock();
          comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

      recv(addr_soc[2],buffer,1,0);
      time_beg = clock();
    //receving Y from evaluator.===============================================
    recv(addr_soc[2], buffer, sizeof(block) * gc.m, 0);
    memcpy(computedOutputMap,buffer,sizeof(block) * gc.m);
    printf("receved Y from evaluator\no/p : ");

      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes += sizeof(block) * gc.m;

    // for(int i=0;i<5;i++){
    //  print128_num(computedOutputMap[i]);
    // }
      time_beg = clock();//computation time
    assert(garble_map_outputs(outputMap, computedOutputMap, outputVals, gc.m) == GARBLE_OK);
      time_end = clock();
  		comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;


    cout<<"\n\nOUTPUT\n-------------------\n";
    for(int i=0;i<gc.m;i++){
      cout<<" "<<outputVals[i]<<" ";
    }
    cout<<"\n-------------------\n\n";

    //Round 4 ============================================================================
      send(addr_soc[2],buffer,1,0);
      time_beg = clock();
    //sending decoding info to evaluator
    memcpy(buffer, outputVals, sizeof(bool)*gc.m);
    send(addr_soc[2], buffer, sizeof(bool) *gc.m,0);
    cout << "Snt decoding info to Evaluator 1" << '\n';
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += sizeof(block) * gc.m;

  }
  else if(id == 2){ //id 2 else

    #ifdef DEBUG
      cout<<"Handling Alice..\nsending initialization msg to Alice\n";
    #endif
  		send(addr_soc[0],buffer,1,0);
  		time_beg = clock();
  	send_input_commits(0);
    recv_input_commits(0);
  		time_end = clock();
  		network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
  		send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;
  		recv_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;


      time_beg = clock();//computation time
    memcpy(recvd_commitment[id], my_Commit, 4 * SHA256_DIGEST_LENGTH);
    //verify commitments
    verifyRecvdCom(recvd_commitment[0][T[2][0][0]], recvd_open[0][T[2][0][0]], INPUT_FIRST_SHARE, 2, 0);
    verifyRecvdCom(recvd_commitment[0][T[2][0][1]], recvd_open[0][T[2][0][1]], INPUT_PER_SHARE, 2, 0);
      time_end = clock();
  		comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;


    //P0_P2_R0 completed
    round_mtx[0][2][0].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[1][2][0].lock();
    round_mtx[1][2][0].unlock();
    round_mtx[2][3][0].lock();
    round_mtx[2][3][0].unlock();

    //Round 2===============================================================================
  		recv(addr_soc[0],buffer,1,0);
  		time_beg = clock();
    recv_input_commits_r2(0);
    send_input_commits_r2(0);
  	  time_end = clock();
  	  network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
  	  send_bytes += 4*4*SHA256_DIGEST_LENGTH;
  	  recv_bytes+= 4*4*SHA256_DIGEST_LENGTH;

    //receving commitments========================================================
      time_beg = clock();//computation time
    char commit_msg[gc.n*2][SHA256_DIGEST_LENGTH];
    int no_of_rounds = (gc.n*2/sha256_in_one_round);
    int blocks_in_last_round = gc.n*2 %blocks_in_one_round;
    extractedLabels0 = garble_allocate_blocks(gc.n);
    gc.output_perms = (bool *)calloc(gc.m, sizeof(bool));
    for (int i = INPUT_4M/2; i < INPUT_4M; ++i){
      decomm[i] = (inputs[i] + b[i]) % 2;
    }
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

      recv(addr_soc[0],buffer,1,0);
      time_beg = clock();

    //Receiving b values==========================================================
    recv(addr_soc[0],buffer, sizeof(bool)*INPUT_4M, 0);
    memcpy(b,buffer,sizeof(bool)*INPUT_4M);

    for(j=0;j< no_of_rounds;++j){
        recv(addr_soc[0],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
        memcpy(&commit_msg[j*sha256_in_one_round],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH);
    }//sending last round
    recv(addr_soc[0],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);
    memcpy(&commit_msg[j*sha256_in_one_round],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH);

    commit_ip[0] = commit_msg;
    #ifdef DEBUG
      printf("Received All commitments from %d!\n",0);
    #endif
    //receved all commitments-----------------------------------------------------

    //receiving the garble circuit================================================
    int size_of_table = (gc.q - gc.nxors);
    no_of_rounds = (2*size_of_table/blocks_in_one_round);
    blocks_in_last_round = (2*size_of_table) %blocks_in_one_round;

    for(j=0;j<no_of_rounds;++j){
      recv(addr_soc[0],buffer,blocks_in_one_round*sizeof(block),0);
      memcpy(gc.table+j*blocks_in_one_round,buffer,blocks_in_one_round*sizeof(block));
    }
    recv(addr_soc[0],buffer,blocks_in_last_round*sizeof(block),0);
    memcpy(gc.table+j*blocks_in_one_round,buffer,blocks_in_last_round*sizeof(block));

    #ifdef DEBUG
      printf("Received GC!\n");
    #endif

    recv(addr_soc[0],buffer,sizeof(bool)*gc.m,0);
    memcpy(gc.output_perms,buffer,sizeof(bool)*gc.m);

    //recive decomitments=========================================================

    recv(addr_soc[0], buffer, sizeof(bool) * INPUT_4M, 0);
    memcpy(decomm+(id*INPUT_4M/4), buffer+(id*INPUT_4M/4), sizeof(bool) * INPUT_4M/4);

    #ifdef DEBUG
    printf("received decomitments\n");
    #endif
    //Receiving Garblers labels for decommitment====================================
    recv(addr_soc[0],buffer,sizeof(block) * gc.n,0);
    memcpy(extractedLabels0,buffer,sizeof(block) * gc.n);

    #ifdef DEBUG
    printf("received extractedLabels\n");
    #endif
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes+= gc.n*2*SHA256_DIGEST_LENGTH+2*size_of_table*sizeof(block)+gc.m+INPUT_4M+ INPUT_4M+sizeof(block)*gc.n;

	  time_beg = clock();//computation time
    garble_hash(&gc, hashh1);
	  time_end = clock();
	  comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    #ifdef DEBUG
      printf("hashh111 Computed\n");
      printf("%s\n", hashh1);
    #endif


    garble_done_mtx.unlock();

    //P0_P2_R0 completed
    round_mtx[0][2][1].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[1][2][1].lock();
    round_mtx[1][2][1].unlock();
    round_mtx[2][3][1].lock();
    round_mtx[2][3][1].unlock();

    //Verify Decommitments===============================================

    // #ifdef DEBUG
    //   printf("Decomitment varification done\n");
    // #endif

    //evaluating  =========================================================
    #ifdef DEBUG
    printf("Evaluation started\n");
    #endif
      time_beg = clock();//computation time
    combine_extractedLabels();
    computedOutputMap = garble_allocate_blocks(gc.m);
    outputVals = (bool*) calloc(gc.m, sizeof(bool));
    if(garble_eval(&gc, extractedLabels, computedOutputMap, outputVals)==GARBLE_ERR){
      printf("Evaluation failed..!\nAborting..\n");
      exit(0);
    }
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

      send(addr_soc[0],buffer,1,0);
  		time_beg = clock();
    // //Round 3=======================================================================
    memcpy(buffer,computedOutputMap,sizeof(block) * gc.m);
    send(addr_soc[0], buffer, sizeof(block) * gc.m, 0);

      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += sizeof(block) * gc.m;

    //Round 4 ============================================================================
      recv(addr_soc[0],buffer,1,0);
      time_beg = clock();
    //sending decoding info to evaluator
    outputVals = (bool*) calloc(gc.m, sizeof(bool));
    recv(addr_soc[0], buffer, sizeof(bool) *gc.m,0);
    memcpy(outputVals, buffer, sizeof(bool)*gc.m);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes += sizeof(block) * gc.m;

    cout<<"\n\nOUTPUT\n-------------------\n";
    for(int i=0;i<gc.m;i++){
      cout<<" "<<outputVals[i]<<" ";
    }
    cout<<"\n-------------------\n\n";  }
}

// Garbler 1 v/s Evaluator 2
int p0_p3_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];
  clock_t time_beg, time_end;
  if(id == 0){

      recv(addr_soc[3],buffer,1,0);
      time_beg = clock();
    recv_input_commits(3);
    send_input_commits(3);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;
      recv_bytes+= 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

      time_beg = clock();//computation time
    //verify commitments
    verifyRecvdCom(recvd_commitment[3][T[3][0][0]], recvd_open[3][T[3][0][0]], INPUT_PER_SHARE, 0, 3);
    verifyRecvdCom(recvd_commitment[3][T[3][0][1]], recvd_open[3][T[3][0][1]], INPUT_PER_SHARE, 0, 3);
      time_end = clock();
  		comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;


    //P0_P3_R0 completed
    round_mtx[0][3][0].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[0][1][0].lock();
    round_mtx[0][1][0].unlock();
    round_mtx[0][2][0].lock();
    round_mtx[0][2][0].unlock();

    //Round 2===============================================================================

      send(addr_soc[3],buffer,1,0);
      time_beg = clock();
    send_input_commits_r2(3);
    recv_input_commits_r2(3);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*4*SHA256_DIGEST_LENGTH;
      recv_bytes+= 4*4*SHA256_DIGEST_LENGTH;


    garble_done_mtx.lock();
    garble_done_mtx.unlock();

      send(addr_soc[3],buffer,1,0);
      time_beg = clock();
    //Sending b values of Evaluator===============================================
    memcpy(buffer, b,sizeof(bool)*INPUT_4M);
    send(addr_soc[3],buffer,sizeof(bool)*INPUT_4M,0);
    //Sent b values to the evaluator----------------------------------------------

    //Sending Cs==================================================================
    //sending comitments for input wires.
    int no_of_rounds = (gc.n*2/sha256_in_one_round);
    int blocks_in_last_round = gc.n*2 %blocks_in_one_round;
    #ifdef DEBUG
      printf("Sending commitments...\n");
      // printf("no of rounds = %d ; blk_in lst_round %d\n",no_of_rounds,blocks_in_last_round);
    #endif

    int j;
    for( j=0;j< no_of_rounds;++j){
        memcpy(buffer,&commit_msg[j*sha256_in_one_round],sha256_in_one_round*SHA256_DIGEST_LENGTH);
        send(addr_soc[3],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
    }//sending last round
    memcpy(buffer,&commit_msg[j*sha256_in_one_round],blocks_in_last_round*SHA256_DIGEST_LENGTH);
    send(addr_soc[3],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);

    //Sent Cs----------------------------------------------------------------------

    //Sending Hash==================================================================
    #ifdef DEBUG
      printf("Sending hash...\n");
      printf("%s\n",hashh1);
    #endif

    memcpy(buffer,hashh1,SHA256_DIGEST_LENGTH);
    send(addr_soc[3],buffer,SHA256_DIGEST_LENGTH,0);

    //Sent Hash---------------------------------------------------------------------

    //Send Decommitments============================================================
    #ifdef DEBUG
      printf("Senting Decomitment info!\n");
    #endif

    //Garbler's index of decommitment
    memcpy(buffer,decom, sizeof(bool) * INPUT_4M);
    send(addr_soc[3], buffer, sizeof(bool) * INPUT_4M, 0);
    //Sent Decommitments-------------------------------------------------------------

    //Garblers labels for decommit
    memcpy(buffer, extractedLabels, sizeof(block) * gc.n);
    send(addr_soc[3], buffer, sizeof(block) * gc.n,0);

      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += INPUT_4M*2+gc.n*2*SHA256_DIGEST_LENGTH+SHA256_DIGEST_LENGTH+sizeof(block) * gc.n;

    //P0_P3_R1 completed
    round_mtx[0][3][1].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[0][1][1].lock();
    round_mtx[0][1][1].unlock();
    round_mtx[0][2][1].lock();
    round_mtx[0][2][1].unlock();

    //Round 3=======================================================================

  }
  else if(id == 3){

    #ifdef DEBUG
      cout<<"Handling Alice..\nsending initialization msg to Alice\n";
    #endif
      send(addr_soc[0],buffer,1,0);
      time_beg = clock();
    send_input_commits(0);
    recv_input_commits(0);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;
      recv_bytes+= 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

      time_beg = clock();//computation time
    //verify commitments
    verifyRecvdCom(recvd_commitment[0][T[3][0][0]], recvd_open[0][T[3][0][0]], INPUT_FIRST_SHARE, 3, 0);
    verifyRecvdCom(recvd_commitment[0][T[3][0][1]], recvd_open[0][T[3][0][1]], INPUT_PER_SHARE, 3, 0);
      time_end = clock();
  		comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    //P0_P3_R0 completed
    round_mtx[0][3][0].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[1][3][0].lock();
    round_mtx[1][3][0].unlock();
    round_mtx[2][3][0].lock();
    round_mtx[2][3][0].unlock();

    //Round 2===============================================================================

      recv(addr_soc[0],buffer,1,0);
      time_beg = clock();
    recv_input_commits_r2(0);
    send_input_commits_r2(0);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*4*SHA256_DIGEST_LENGTH;
      recv_bytes+= 4*4*SHA256_DIGEST_LENGTH;

      recv(addr_soc[0],buffer,1,0);
      time_beg = clock();
    //Receiving b values==========================================================
    recv(addr_soc[0],buffer, sizeof(bool)*INPUT_4M, 0);
    memcpy(b,buffer,sizeof(bool)*INPUT_4M);

    #ifdef DEBUG
      printf("Received b values\n");
    #endif
    //receving commitments========================================================
    char commit_msg[gc.n*2][SHA256_DIGEST_LENGTH];
    int no_of_rounds = (gc.n*2/sha256_in_one_round);
    int blocks_in_last_round = gc.n*2 %blocks_in_one_round;

    int j;
    for( j=0;j< no_of_rounds;++j){
        recv(addr_soc[0],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
        memcpy(&commit_msg[j*sha256_in_one_round],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH);
    }//sending last round
    recv(addr_soc[0],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);
    memcpy(&commit_msg[j*sha256_in_one_round],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH);


    commit_ip[0] = commit_msg;
    #ifdef DEBUG
      printf("Received All commitments from %d!\n",id);
    #endif
    //receved all commitments-----------------------------------------------------

    //recieve hash of GC=========================================================
    recv(addr_soc[0],buffer,SHA256_DIGEST_LENGTH,0);
    memcpy(hashh,buffer,SHA256_DIGEST_LENGTH);
    gc_hashh[0] = hashh;

    #ifdef DEBUG
      printf("Received Hash of GC\n");
      printf("%s\n", hashh);
    #endif
    //recive decomitments=========================================================
    for (int i = INPUT_4M/2; i < INPUT_4M; ++i){
      decomm[i] = (inputs[i] + b[i]) % 2;
    }

    recv(addr_soc[0], buffer, sizeof(bool) * INPUT_4M, 0);
    memcpy(decomm+(id*INPUT_4M/4), buffer+(id*INPUT_4M/4), sizeof(bool) * INPUT_4M/4);

    #ifdef DEBUG
    printf("received decomitments\n");
    #endif

    //Receiving Garblers labels for decommitment====================================
    recv(addr_soc[0], buffer, sizeof(block) * gc.n,0);

    extractedLabels0 = garble_allocate_blocks(gc.n);
    memcpy(extractedLabels0,buffer,sizeof(block) * gc.n);

    #ifdef DEBUG
    printf("received extractedLabels\n");
    #endif
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes+= INPUT_4M*2+gc.n*2*SHA256_DIGEST_LENGTH+SHA256_DIGEST_LENGTH+sizeof(block) * gc.n;

    garble_done_mtx.lock();
    garble_done_mtx.unlock();

      time_beg = clock();//computation time

    // varification of commitment==================================================
    if(memcmp(commit_ip[0],commit_ip[1],gc.n*2*SHA256_DIGEST_LENGTH) != 0){
        cout<<"commitment for G1&G2 are not equal\naborting..\n";
        // exit(0);
    }

    // //checking hash of GC and received hashes=====================================
    if(memcmp(hashh,hashh1,SHA256_DIGEST_LENGTH)!=0){
      cout<<"hash is not equal to the GC\n";
      printf("hash calc:%s\n", hashh1);
      printf("hash received:%s\n", hashh);
      // exit(0);
    }
    else{
        cout<<"Hashes are equal!!!\n";
    }

      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    //P0_P3_R1 completed
    round_mtx[0][3][1].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[1][3][1].lock();
    round_mtx[1][3][1].unlock();
    round_mtx[2][3][1].lock();
    round_mtx[2][3][1].unlock();

    //Round 3===============================================================================


  }
}

// Garbler 2 v/s Evaluator 1
int p1_p2_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];
  clock_t time_beg, time_end;
  if(id == 1){

    #ifdef DEBUG
      std::cout << "Waiting for Cleve's message" << '\n';
    #endif

      recv(addr_soc[2],buffer,1,0);
      time_beg = clock();
    recv_input_commits(2);
    send_input_commits(2);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;
      recv_bytes+= 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

      time_beg = clock();//computation time
    //verify commitments
    verifyRecvdCom(recvd_commitment[2][T[2][1][0]], recvd_open[2][T[2][1][0]], INPUT_FIRST_SHARE, 1, 2);
    verifyRecvdCom(recvd_commitment[2][T[2][1][1]], recvd_open[2][T[2][1][1]], INPUT_PER_SHARE, 1, 2);
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    //P1_P2_R0 completed
    round_mtx[1][2][0].unlock();
  	//Waiting for other threds to complete round 0(1)
  	round_mtx[0][1][0].lock();
  	round_mtx[0][1][0].unlock();
  	round_mtx[1][3][0].lock();
  	round_mtx[1][3][0].unlock();

    //Round 2===============================================================================
      send(addr_soc[2],buffer,1,0);
      time_beg = clock();
    send_input_commits_r2(2);
    recv_input_commits_r2(2);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*4*SHA256_DIGEST_LENGTH;
      recv_bytes+= 4*4*SHA256_DIGEST_LENGTH;

    garble_done_mtx.lock();
    garble_done_mtx.unlock();

      send(addr_soc[2],buffer,1,0);
      time_beg = clock();
    //Sending b values of Evaluator===============================================
    memcpy(buffer, b,sizeof(bool)*INPUT_4M);
    send(addr_soc[2],buffer,sizeof(bool)*INPUT_4M,0);
    //Sent b values to the evaluator----------------------------------------------

    //Sending Cs==================================================================
    //sending comitments for input wires.
    int no_of_rounds = (gc.n*2/sha256_in_one_round);
    int blocks_in_last_round = gc.n*2 %blocks_in_one_round;
    #ifdef DEBUG
      printf("Sending commitments...\n");
      // printf("no of rounds = %d ; blk_in lst_round %d\n",no_of_rounds,blocks_in_last_round);
    #endif

    int j;
    for( j=0;j< no_of_rounds;++j){
        memcpy(buffer,&commit_msg[j*sha256_in_one_round],sha256_in_one_round*SHA256_DIGEST_LENGTH);
        send(addr_soc[2],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
    }//sending last round
    memcpy(buffer,&commit_msg[j*sha256_in_one_round],blocks_in_last_round*SHA256_DIGEST_LENGTH);
    send(addr_soc[2],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);

    //Sent Cs----------------------------------------------------------------------

    //Sending Hash==================================================================
    #ifdef DEBUG
      printf("Sending hash...\n");
      printf("%s\n",hashh1);
    #endif

    memcpy(buffer,hashh1,SHA256_DIGEST_LENGTH);
    send(addr_soc[2],buffer,SHA256_DIGEST_LENGTH,0);

    //Sent Hash---------------------------------------------------------------------

    //Send Decommitments============================================================
    #ifdef DEBUG
      printf("Senting Decomitment info!\n");
    #endif

    //Garbler's index of decommitment
    memcpy(buffer,decom, sizeof(bool) * INPUT_4M);
    send(addr_soc[2], buffer, sizeof(bool) * INPUT_4M, 0);

    //Garblers labels for decommit
    memcpy(buffer, extractedLabels, sizeof(block) * gc.n);
    send(addr_soc[2], buffer, sizeof(block) * gc.n,0);
    //Sent Decommitments-------------------------------------------------------------

      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += INPUT_4M*2+gc.n*2*SHA256_DIGEST_LENGTH+SHA256_DIGEST_LENGTH+sizeof(block) * gc.n;

    //P1_P2_R1 completed
    round_mtx[1][2][1].unlock();
  	//Waiting for other threds to complete round 0(1)
  	round_mtx[0][1][1].lock();
  	round_mtx[0][1][1].unlock();
  	round_mtx[1][3][1].lock();
  	round_mtx[1][3][1].unlock();

    //Round 3=======================================================================

  }
  else if(id == 2){

      send(addr_soc[1],buffer,1,0);
      time_beg = clock();
    send_input_commits(1);
    recv_input_commits(1);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;
      recv_bytes+= 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

    time_beg = clock();//computation time
    //verify commitments
    verifyRecvdCom(recvd_commitment[1][T[2][1][0]], recvd_open[1][T[2][1][0]], INPUT_FIRST_SHARE, 2, 1);
    verifyRecvdCom(recvd_commitment[1][T[2][1][1]], recvd_open[1][T[2][1][1]], INPUT_PER_SHARE, 2, 1);
    time_end = clock();
		comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    //P1_P2_R0 completed
    round_mtx[1][2][0].unlock();
    //Waiting for other threds to complete round 0(1)
    round_mtx[0][2][0].lock();
    round_mtx[0][2][0].unlock();
    round_mtx[2][3][0].lock();
    round_mtx[2][3][0].unlock();

	  //Round 2===============================================================================
      recv(addr_soc[1],buffer,1,0);
      time_beg = clock();
    recv_input_commits_r2(1);
    send_input_commits_r2(1);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*4*SHA256_DIGEST_LENGTH;
      recv_bytes+= 4*4*SHA256_DIGEST_LENGTH;

      recv(addr_soc[1],buffer,1,0);
      time_beg = clock();
    //Receiving b values==========================================================
    recv(addr_soc[1],buffer, sizeof(bool)*INPUT_4M, 0);
    memcpy(b+INPUT_4M,buffer,sizeof(bool)*INPUT_4M);

    #ifdef DEBUG
      printf("Received b values\n");
    #endif

    //receving commitments========================================================
    char commit_msg[gc.n*2][SHA256_DIGEST_LENGTH];
    int no_of_rounds = (gc.n*2/sha256_in_one_round);
    int blocks_in_last_round = gc.n*2 %blocks_in_one_round;

    int j;
    for( j=0;j< no_of_rounds;++j){
        recv(addr_soc[1],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
        memcpy(&commit_msg[j*sha256_in_one_round],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH);
    }//sending last round
    recv(addr_soc[1],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);
    memcpy(&commit_msg[j*sha256_in_one_round],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH);


    commit_ip[1] = commit_msg;
    #ifdef DEBUG
      printf("Received All commitments from %d!\n",id);
    #endif
    //receved all commitments-----------------------------------------------------


    //recieve hash of GC=========================================================
    recv(addr_soc[1],buffer,SHA256_DIGEST_LENGTH,0);
    memcpy(hashh,buffer,SHA256_DIGEST_LENGTH);
    gc_hashh[1] = hashh;

    #ifdef DEBUG
      printf("Received Hash of GC\n");
      printf("%s\n", hashh);
    #endif

      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes+= INPUT_4M*2+gc.n*2*SHA256_DIGEST_LENGTH+SHA256_DIGEST_LENGTH+sizeof(block) * gc.n;

    garble_done_mtx.lock();
    garble_done_mtx.unlock();

      time_beg = clock();//computation time

    //varification of commitment==================================================
    if(memcmp(b,b+INPUT_4M,sizeof(bool)*INPUT_4M)!=0){
      printf("received b values are not equal for P3\t aborting...\n");
    }

    if(memcmp(commit_ip[0],commit_ip[1],gc.n*2*SHA256_DIGEST_LENGTH) != 0){
        cout<<"commitment for G1&G2 are not equal\naborting..\n";
        // exit(0);
    }

    // //checking hash of GC and received hashes=====================================
    if(memcmp(hashh,hashh1,SHA256_DIGEST_LENGTH)!=0){
      cout<<"hash is not equal to the GC\n";
      printf("hash calc:%s\n", hashh1);
      printf("hash received:%s\n", hashh);
    }
    else{
        cout<<"Hashes are equal!!!\n";
    }

      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    //recive decomitments=========================================================
    for (int i = INPUT_4M/2; i < INPUT_4M; ++i){
        decomm[i] = (inputs[i] + b[i]) % 2;
    }

    recv(addr_soc[1], buffer, sizeof(bool) * INPUT_4M, 0);
    memcpy(decomm+(id*INPUT_4M/4), buffer+(id*INPUT_4M/4), sizeof(bool) * INPUT_4M/4);

    #ifdef DEBUG
      printf("received decomitments\n");
    #endif

    //Receiving Garblers labels for decommitment====================================
    recv(addr_soc[1], buffer, sizeof(block) * gc.n,0);
    extractedLabels1 = garble_allocate_blocks(gc.n);
    memcpy(extractedLabels1,buffer,sizeof(block) * gc.n);

    #ifdef DEBUG
      printf("received extractedLabels\n");
    #endif

    //P1_P2_R1 completed
    round_mtx[1][2][1].unlock();
    //Waiting for other threds to complete round 0(1)
    round_mtx[0][2][1].lock();
    round_mtx[0][2][1].unlock();
    round_mtx[2][3][1].lock();
    round_mtx[2][3][1].unlock();

    //Verify Decommitments===============================================
    // for (int i = 0; i < INPUT_4M; ++i){
    //     if(verify_commit((char*)&commit_msg[2*i+decomm[i]][0], extractedLabels[i], NULL, COMMIT_SCHEME_SHA256) == false){
    //        printf("Commitment varification(at %d) failed\n",i);
    //        exit(0);
    //      }
    //    }

    // #ifdef DEBUG
    //   printf("Decomitment varification done\n");
    // #endif

    // //evaluating  =========================================================
    // #ifdef DEBUG
    //   printf("Evaluation started\n");
    // #endif

    // printf("Evaluation started\n");
    // if(garble_eval(&gc, extractedLabels, computedOutputMap, outputVals)==GARBLE_ERR){
    //     printf("Evaluation failed..!\nAborting..\n");
    //     exit(0);
    // }

  }

}

// Garbler 2 v/s Evaluator 2
int p1_p3_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];
  clock_t time_beg, time_end;
  if(id == 1){
      recv(addr_soc[3],buffer,1,0);
      time_beg = clock();
    recv_input_commits(3);
    send_input_commits(3);
      time_end = clock();
  	  network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
  	  send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;
  	  recv_bytes+= 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

    //
    //verify commitments
    verifyRecvdCom(recvd_commitment[3][T[3][1][0]], recvd_open[3][T[3][1][0]], INPUT_FIRST_SHARE, 1, 3);
    verifyRecvdCom(recvd_commitment[3][T[3][1][1]], recvd_open[3][T[3][1][1]], INPUT_PER_SHARE, 1, 3);


    //P1_P3_R0 completed
    round_mtx[1][3][0].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[0][1][0].lock();
    round_mtx[0][1][0].unlock();
    round_mtx[1][2][0].lock();
    round_mtx[1][2][0].unlock();

    //Round 2===============================================================================
      send(addr_soc[3],buffer,1,0);
      time_beg = clock();
    send_input_commits_r2(3);
    recv_input_commits_r2(3);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*4*SHA256_DIGEST_LENGTH;
      recv_bytes+= 4*4*SHA256_DIGEST_LENGTH;

    garble_done_mtx.lock();
    garble_done_mtx.unlock();

    //Sending Cs==================================================================
    //sending comitments for input wires.
    int no_of_rounds = (gc.n*2/sha256_in_one_round),j;
    int blocks_in_last_round = gc.n*2 %blocks_in_one_round;
    #ifdef DEBUG
    printf("Sending commitments...\n");
    // printf("no of rounds = %d ; blk_in lst_round %d\n",no_of_rounds,blocks_in_last_round);
    #endif

      //dummy send (for exact timing calculations)
      send(addr_soc[3],buffer,1,0);
      time_beg = clock();

    //Sending b values of Evaluator===============================================
    memcpy(buffer, b+3*INPUT_4M/4,sizeof(bool)*INPUT_4M/4);
    send(addr_soc[3],buffer,sizeof(bool)*INPUT_4M/4,0);
    //Sent b values to the evaluator----------------------------------------------

    for(j=0;j< no_of_rounds;++j){
        memcpy(buffer,&commit_msg[j*sha256_in_one_round],sha256_in_one_round*SHA256_DIGEST_LENGTH);
        send(addr_soc[3],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
    }//sending last round
    memcpy(buffer,&commit_msg[j*sha256_in_one_round],blocks_in_last_round*SHA256_DIGEST_LENGTH);
    send(addr_soc[3],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);

    //Sent Cs----------------------------------------------------------------------

    //Sending GC===================================================================
    int size_of_table = (gc.q - gc.nxors);
    no_of_rounds = (2*size_of_table/blocks_in_one_round);
    blocks_in_last_round = (2*size_of_table) %blocks_in_one_round;

    #ifdef DEBUG
      printf("Sending GC...\n");
      // printf("no of rounds = %d ;blocks in last round= %d\n",no_of_rounds,blocks_in_last_round);
    #endif

    for(j=0;j<no_of_rounds;++j){
      memcpy(buffer,gc.table+j*blocks_in_one_round,blocks_in_one_round*sizeof(block));
      send(addr_soc[3],buffer,blocks_in_one_round*sizeof(block),0);
    }
    memcpy(buffer,gc.table+j*blocks_in_one_round,blocks_in_last_round*sizeof(block));
    send(addr_soc[3],buffer,blocks_in_last_round*sizeof(block),0);

    //send output_perms
    memcpy(buffer,gc.output_perms,sizeof(bool)*gc.m);
    send(addr_soc[3],buffer,sizeof(bool)*gc.m,0);
    //Sent GC-----------------------------------------------------------------------

    //Send Decommitments============================================================
    #ifdef DEBUG
    printf("Senting Decomitment info!\n");
    #endif

    //Garbler's index of decommitment
    memcpy(buffer,decom, sizeof(bool) * INPUT_4M);
    send(addr_soc[3], buffer, sizeof(bool) * INPUT_4M, 0);
    //Sent Decommitments-------------------------------------------------------------
    //Garblers labels for decommit
    memcpy(buffer,extractedLabels,sizeof(block) * gc.n);
    send(addr_soc[3],buffer,sizeof(block) * gc.n,0);

      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += gc.n*2*SHA256_DIGEST_LENGTH+2*size_of_table*sizeof(block)+gc.m+INPUT_4M+ INPUT_4M+sizeof(block)*gc.n;

    //P1_P3_R1 completed
    round_mtx[1][3][1].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[0][1][1].lock();
    round_mtx[0][1][1].unlock();
    round_mtx[1][2][1].lock();
    round_mtx[1][2][1].unlock();

    // Round 3=======================================================================

    //receving Y from evaluator.===============================================

    computedOutputMap = garble_allocate_blocks(gc.m);
    outputVals = (bool*) calloc(gc.m, sizeof(bool));
      recv(addr_soc[3],buffer,1,0);
      time_beg = clock();
    recv(addr_soc[3], buffer, sizeof(block) * gc.m, 0);
    memcpy(computedOutputMap,buffer,sizeof(block) * gc.m);
    printf("receved Y from evaluator\no/p : ");
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes += sizeof(block) * gc.m;

      time_beg = clock();//computation time
    assert(garble_map_outputs(outputMap, computedOutputMap, outputVals, gc.m) == GARBLE_OK);
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    cout<<"\n\nOUTPUT\n-------------------\n";
    for(int i=0;i<gc.m;i++){
      cout<<" "<<outputVals[i]<<" ";
    }
    cout<<"\n-------------------\n\n";

    //Round 4 ============================================================================
      send(addr_soc[3],buffer,1,0);
      time_beg = clock();
    //sending decoding info to evaluator
    memcpy(buffer, outputVals, sizeof(bool)*gc.m);
    send(addr_soc[3], buffer, sizeof(bool) *gc.m,0);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += sizeof(block) * gc.m;

    cout << "Snt decoding info to Evaluator 2" << '\n';

  }
  else if(id == 3){
      send(addr_soc[1],buffer,1,0);
      time_beg = clock();
    send_input_commits(1);
    recv_input_commits(1);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;
      recv_bytes+= 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

      time_beg = clock();//computation time
    //verify commitments
    verifyRecvdCom(recvd_commitment[1][T[3][1][0]], recvd_open[1][T[3][1][0]], INPUT_FIRST_SHARE, 3, 1);
    verifyRecvdCom(recvd_commitment[1][T[3][1][1]], recvd_open[1][T[3][1][1]], INPUT_PER_SHARE, 3, 1);
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    //P1_P3_R0 completed
    round_mtx[1][3][0].unlock();
    //Waiting for other threds to complete round 0(1)
    round_mtx[2][3][0].lock();
    round_mtx[2][3][0].unlock();
    round_mtx[0][3][0].lock();
    round_mtx[0][3][0].unlock();

    //Round 2===============================================================================
      recv(addr_soc[1],buffer,1,0);
      time_beg = clock();
    recv(addr_soc[1],buffer, sizeof(bool)*INPUT_4M/4, 0);
    memcpy(b+3*INPUT_4M/4,buffer,sizeof(bool)*INPUT_4M/4);
    recv_input_commits_r2(1);
    send_input_commits_r2(1);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*4*SHA256_DIGEST_LENGTH;
      recv_bytes+= 4*4*SHA256_DIGEST_LENGTH;

    #ifdef DEBUG
      printf("Received b values from bob\n");
    #endif

    if(memcmp(b+INPUT_4M/4,b+3*INPUT_4M/4,sizeof(bool)*INPUT_4M/4)!=0){
      printf("received b values are not equal for P4\t aborting...\n");
    }

    //receving commitments========================================================

    int no_of_rounds = (gc.n*2/sha256_in_one_round),j;
    int blocks_in_last_round = gc.n*2 %blocks_in_one_round;
    char commit_msg[gc.n*2][SHA256_DIGEST_LENGTH];

      recv(addr_soc[1],buffer,1,0);
      time_beg = clock();

    //Receiving b values==========================================================
    recv(addr_soc[1],buffer, sizeof(bool)*INPUT_4M/4, 0);
    memcpy(b+3*INPUT_4M/4,buffer,sizeof(bool)*INPUT_4M/4);

    for(j=0;j< no_of_rounds;++j){
        recv(addr_soc[1],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
        memcpy(&commit_msg[j*sha256_in_one_round],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH);
    }//sending last round
    recv(addr_soc[1],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);
    memcpy(&commit_msg[j*sha256_in_one_round],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH);

    commit_ip[1] = commit_msg;
    #ifdef DEBUG
      printf("Received All commitments from %d!\n",0);
    #endif
    //receved all commitments-----------------------------------------------------

    //receiving the garble circuit================================================
    int size_of_table = (gc.q - gc.nxors);
    no_of_rounds = (2*size_of_table/blocks_in_one_round);
    blocks_in_last_round = (2*size_of_table) %blocks_in_one_round;

    for(j=0;j<no_of_rounds;++j){
      recv(addr_soc[1],buffer,blocks_in_one_round*sizeof(block),0);
      memcpy(gc.table+j*blocks_in_one_round,buffer,blocks_in_one_round*sizeof(block));
    }
    recv(addr_soc[1],buffer,blocks_in_last_round*sizeof(block),0);
    memcpy(gc.table+j*blocks_in_one_round,buffer,blocks_in_last_round*sizeof(block));

    #ifdef DEBUG
    printf("Received GC!\n");
    #endif

    extractedLabels1 = garble_allocate_blocks(gc.n);
    gc.output_perms = (bool *)calloc(gc.m, sizeof(bool));

    recv(addr_soc[1],buffer,sizeof(bool)*gc.m,0);
    memcpy(gc.output_perms,buffer,sizeof(bool)*gc.m);

    //recive decomitments=========================================================
    for (int i = INPUT_4M/2; i < INPUT_4M; ++i){
        decomm[i] = (inputs[i] + b[i]) % 2;
    }

    recv(addr_soc[1], buffer, sizeof(bool) * INPUT_4M, 0);
    memcpy(decomm+(id*INPUT_4M/4), buffer+(id*INPUT_4M/4), sizeof(bool) * INPUT_4M/4);

    //Receiving Garblers labels for decommitment====================================
    recv(addr_soc[1],buffer,sizeof(block) * gc.n,0);
    memcpy(extractedLabels1,buffer,sizeof(block) * gc.n);
    #ifdef DEBUG
    printf("received extractedLabels\n");
    #endif

      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes+= gc.n*2*SHA256_DIGEST_LENGTH+2*size_of_table*sizeof(block)+gc.m+INPUT_4M+ INPUT_4M+sizeof(block)*gc.n;

      time_beg = clock();//computation time
    garble_hash(&gc, hashh1);
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    #ifdef DEBUG
      printf("hashh111 Computed\n");
      printf("%s\n", hashh1);
    #endif

    garble_done_mtx.unlock();

    //P1_P3_R1 completed
    round_mtx[1][3][1].unlock();
    //Waiting for other threds to complete round 0(1)
    round_mtx[2][3][1].lock();
    round_mtx[2][3][1].unlock();
    round_mtx[0][3][1].lock();
    round_mtx[0][3][1].unlock();

    //evaluating  =========================================================
    #ifdef DEBUG
    printf("Evaluation started\n");
    #endif
      time_beg = clock();//computation time
    combine_extractedLabels();
    computedOutputMap = garble_allocate_blocks(gc.m);
    outputVals = (bool*) calloc(gc.m, sizeof(bool));
    if(garble_eval(&gc, extractedLabels, computedOutputMap, outputVals)==GARBLE_ERR){
      printf("Evaluation failed..!\nAborting..\n");
      exit(0);
    }
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    // //Round 3=======================================================================
    //Round 4 ============================================================================
      send(addr_soc[1],buffer,1,0);
      time_beg = clock();
    memcpy(buffer,computedOutputMap,sizeof(block) * gc.m);
    send(addr_soc[1], buffer, sizeof(block) * gc.m, 0);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += sizeof(block) * gc.m;


    //Round 4 ============================================================================
      recv(addr_soc[2],buffer,1,0);
      time_beg = clock();
    //sending decoding info to evaluator
    outputVals = (bool*) calloc(gc.m, sizeof(bool));
    recv(addr_soc[1], buffer, sizeof(bool) *gc.m,0);
    memcpy(outputVals, buffer, sizeof(bool)*gc.m);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes += sizeof(block) * gc.m;

    cout<<"\n\nOUTPUT\n-------------------\n";
    for(int i=0;i<gc.m;i++){
      cout<<" "<<outputVals[i]<<" ";
    }
    cout<<"\n-------------------\n\n";
  }
}

//  Evaluator 1 v/s Evaluator 2
int p2_p3_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];
  clock_t time_beg, time_end;
  if(id == 2){
      send(addr_soc[3],buffer,1,0);
      time_beg = clock();
    send_input_commits(3);
    recv_input_commits(3);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;
      recv_bytes+= 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

      time_beg = clock();//computation time
    //verify commitments
    verifyRecvdCom(recvd_commitment[3][T[3][2][0]], recvd_open[3][T[3][2][0]], INPUT_FIRST_SHARE, 2, 3);
    verifyRecvdCom(recvd_commitment[3][T[3][2][1]], recvd_open[3][T[3][2][1]], INPUT_PER_SHARE, 2, 3);
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    //P2_P3_R0 completed
    round_mtx[2][3][0].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[0][2][0].lock();
    round_mtx[0][2][0].unlock();
    round_mtx[1][2][0].lock();
    round_mtx[1][2][0].unlock();
	  printf("\n*****\nRound one is complete ...\n******\n");

    //Round 2===============================================================================
      send(addr_soc[3],buffer,1,0);
      time_beg = clock();
    send_input_commits_r2(3);
    recv_input_commits_r2(3);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*4*SHA256_DIGEST_LENGTH;
      recv_bytes+= 4*4*SHA256_DIGEST_LENGTH;

    //P2_P3_R1 completed
    round_mtx[2][3][1].unlock();
	  //Waiting for other threds to complete round 0(1)
    round_mtx[0][2][1].lock();
    round_mtx[0][2][1].unlock();
    round_mtx[1][2][1].lock();
    round_mtx[1][2][1].unlock();
  }
  else if(id == 3){
      recv(addr_soc[2],buffer,1,0);
      time_beg = clock();
    recv_input_commits(2);
    send_input_commits(2);
      time_end = clock();
  	  network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
  	  send_bytes += 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;
  	  recv_bytes+= 4*SHA256_DIGEST_LENGTH +2*INPUT_FIRST_SHARE;

    memcpy(recvd_commitment[id], my_Commit, 4 * SHA256_DIGEST_LENGTH);

      time_beg = clock();//computation time
    //verify commitments
    verifyRecvdCom(recvd_commitment[2][T[2][3][0]], recvd_open[2][T[2][3][0]], INPUT_FIRST_SHARE, 3, 2);
    verifyRecvdCom(recvd_commitment[2][T[2][3][1]], recvd_open[2][T[2][3][1]], INPUT_PER_SHARE, 3, 2);
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    //P2_P3_R0 completed
    round_mtx[2][3][0].unlock();
    //Waiting for other threds to complete round 0(1)
    round_mtx[0][3][0].lock();
    round_mtx[0][3][0].unlock();
    round_mtx[1][3][0].lock();
    round_mtx[1][3][0].unlock();
  	printf("\n*****\nRound one is complete ...\n******\n");

  	//Round 2===============================================================================
      recv(addr_soc[2],buffer,1,0);
      time_beg = clock();
    recv_input_commits_r2(2);
    send_input_commits_r2(2);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += 4*4*SHA256_DIGEST_LENGTH;
      recv_bytes+= 4*4*SHA256_DIGEST_LENGTH;

    //P2_P3_R1 completed
    round_mtx[2][3][1].unlock();
    //Waiting for other threds to complete round 0(1)
    round_mtx[0][3][1].lock();
    round_mtx[0][3][1].unlock();
    round_mtx[1][3][1].lock();
    round_mtx[1][3][1].unlock();
  }
}


void garbler(){
  sockaddr client_addr;
  socklen_t addr_size = sizeof(client_addr);

  u_char buffer[MAX_PAYLOAD_SIZE];
  int server_fd,i,j;
  clock_t time_beg, time_end;

  //Connecting to Evaluator 1==============================================
  addr_soc[2] = socket_connect(ip[2],SERVER_PORT);
  //Connecting to Evaluator 2==============================================
  addr_soc[3] = socket_connect(ip[3],SERVER_PORT2);

    // dummy send (for exact timing calculations)
    // recv(server_fd,buffer,1,0);
    // time_beg = clock();
  recv(addr_soc[2],buffer,INPUT_4M,0);
    // time_end = clock();
    // network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    // recv_bytes += INPUT_4M/2+3;

  cout<<"Got "<<buffer[1]<<" from Evaluator 1\n";
    #ifdef DEBUG
      cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif

    // time_beg = clock();//computation time
  if(buffer[1]=='A'){
    cout<<"I\'m Alice, garbler 1(P0)\n";
    id = 0;
    //sampling Alice's inputs
    for (i = 0; i < INPUT_4M/4; ++i) {
            inputs[i]= rand() % 2;
    }
    //gen and copy commitments
    genCommit(my_Commit, my_Decommit,id,inputs);

    //Copying evaluator's input
    // memcpy(inputs+INPUT_4M/2, buffer+2, sizeof(bool) * INPUT_4M/4);
  }
  else if(buffer[1]=='B'){
    cout<<"I\'m Bob, garbler 2(P1)\n";
    id = 1;
    //Sampling bob's input
    for (i = INPUT_4M/4; i < INPUT_4M/2; ++i){
            inputs[i]= rand() % 2;
    }
    //gen and copy commitments
    genCommit(my_Commit, my_Decommit,id,inputs);

    //Copying evaluator's input
    // memcpy(inputs+((3*INPUT_4M)/4), buffer+2, sizeof(bool) * INPUT_4M/4);
  }

  if(id == 0){//Alice
    server_fd = socket_bind_listen(ip[0],SERVER_PORT3);
    if(server_fd<0){
      exit(0);
    }
    if((addr_soc[1]= accept(server_fd,(sockaddr*)(&client_addr) ,&addr_size))<0){
        cout<<"accept failed\n";
        exit(0);
    }
    thread e1 (p0_p2_handler);
    thread e2 (p0_p3_handler);
    thread g1 (p0_p1_handler);
    e1.join();
    e2.join();
    g1.join();
  }
  else{//Bob
    addr_soc[0] = socket_connect(ip[0],SERVER_PORT3);
    thread e1 (p1_p2_handler);
    thread e2 (p1_p3_handler);
    thread g1 (p0_p1_handler);
    e1.join();
    e2.join();
    g1.join();
  }
  #ifdef DEBUG
    // cout<<"garblers working properly\n";
  #endif

}

//P2(evaluator 1) server open for connecting P0,P1 & P2
void evaluator(){
    sockaddr client_addr;
    u_char buffer[MAX_PAYLOAD_SIZE];

    socklen_t addr_size = sizeof(client_addr);
    int server_fd;

    server_fd = socket_bind_listen(ip[2],SERVER_PORT);

    //Sampling inputs for evaluator
    for (size_t i = INPUT_4M/2; i < 3*INPUT_4M/4; ++i) {
            inputs[i]= rand() % 2;
    }
    //gen and copy commitments
    genCommit(my_Commit, my_Decommit,id,inputs);

    // verifyRecvdCom(my_Commit[0],my_Decommit[0],INPUT_FIRST_SHARE,id,0);
    // exit(0);
    //allocating global variables
    gc.table = (block*) calloc(gc.q - gc.nxors,garble_table_size(&gc));
    extractedLabels = garble_allocate_blocks(gc.n);
    computedOutputMap = garble_allocate_blocks(gc.m);
    outputVals = (bool*) calloc(gc.m, sizeof(bool));

    if((addr_soc[3] = accept(server_fd,(sockaddr*)(&client_addr) ,&addr_size))<0){
      cout<<"accept failed\n";
    }
    cout<<"Connected to eval2\n";
    //other evaluator(p1) handler
    thread e1 (p2_p3_handler);

    if((addr_soc[0] = accept(server_fd,(sockaddr*)(&client_addr) ,&addr_size))<0){
      cout<<"accept failed\n";
    }
    //starting Alice_handler
    buffer[1]= 'A';
    send(addr_soc[0],buffer,INPUT_4M,0);

    thread g1 (p0_p2_handler);

    if((addr_soc[1] = accept(server_fd,(sockaddr*)(&client_addr) ,&addr_size))<0){
      cout<<"accept failed\n";
    }
    //Starting Bob_handler
    buffer[1]= 'B';
    send(addr_soc[1],buffer,INPUT_4M,0);

    thread g2 (p1_p2_handler);

    #ifdef DEBUG
      // cout<<"\nsoc_id for g1(Alice):"<<addr_soc[0]<<" ,soc_id for g2(Bob):"<<addr_soc[1]<<"\n";
    #endif

    //soft decode and learn the output from
    #ifdef DEBUG
      printf("Eval main 1 waiting for hanlers to exit\n");
    #endif
    close(server_fd);
    e1.join();
    g2.join();
    g1.join();
}

//P3(evaluator 2) server open for connecting P0,P1 & P3
void evaluator2(){
  sockaddr client_addr;
  socklen_t addr_size = sizeof(client_addr);
  int server_fd;

  server_fd = socket_bind_listen(ip[3],SERVER_PORT2);

  //Sampling inputs for evaluator
  for (size_t i = 3*INPUT_4M/4; i < INPUT_4M; ++i) {
          inputs[i]= rand() % 2;
  }
  //gen and copy commitments
  genCommit(my_Commit, my_Decommit,id,inputs);

  //allocating global variables
  gc.table = (block*) calloc(gc.q - gc.nxors,garble_table_size(&gc));
  extractedLabels = garble_allocate_blocks(gc.n);
  computedOutputMap = garble_allocate_blocks(gc.m);
  outputVals = (bool*) calloc(gc.m, sizeof(bool));

  //connecting to the evaluator 1
  addr_soc[2] = socket_connect(ip[2],SERVER_PORT);
  cout<<"Connected to eval1\n";
  thread e1 (p2_p3_handler);

  if((addr_soc[0] = accept(server_fd,(sockaddr*)(&client_addr) ,&addr_size))<0){
    cout<<"accept failed\n";
  }
  //starting Alice_handler
  thread g1 (p0_p3_handler);

  if((addr_soc[1] = accept(server_fd,(sockaddr*)(&client_addr) ,&addr_size))<0){
    cout<<"accept failed\n";
  }
  //Starting Bob_handler
  thread g2 (p1_p3_handler);

  #ifdef DEBUG
    cout<<"\nsoc_id for g1(Alice):"<<addr_soc[0]<<" ,soc_id for g2(Bob):"<<addr_soc[1]<<"\n";
  #endif

  //soft decode and learn the output from
  #ifdef DEBUG
    printf("Eval main waiting for Bob_handler to exit\n");
  #endif
  close(server_fd);
  e1.join();
  g2.join();
  g1.join();
}

int main(int argc, char *argv[]){

    #ifdef DEBUG
      cout<<"configure the ip of each party appropriately,\ncurrent settings\n";
      for(int i=0;i<4;i++){
        cout<<"ip of p"<<i<<" : "<<ip[i]<<"\n";
      }
    #endif

    if(argc !=2){
  		printf("\npass arguments evaluator/garbler  Eg: ./4pc_god e \n e - evaluator1\n f - evaluator2\n g - garbler1or2\n");
    }
  		// exit(0);
    // loading garbled circuit from file
  	build(&gc,GC_FILE);
    //commit_msg=(char*)malloc(gc.n*2*SHA256_DIGEST_LENGTH);

    #ifdef DEBUG
      cout<<"gc file read done..\ngc->n,m,q,r,nxor "<<gc.n<<" , "<<gc.m<<" , "<<gc.q<<" , "<<gc.r<<" , "<<gc.nxors<<"\n";
    #endif

    garble_done_mtx.lock();
    for(int i=0;i<4;++i){
      for(int j=0;j<4;++j){
        for(int k =0;k<4;++k){
          round_mtx[i][j][k].lock();
        }
      }
    }
  	if (argv[1][0]=='e')
    {//starting evaluator p3 in MRZ15
      printf("Stating Evaluator 1..\n");
      id=2; //denoting P2
  		evaluator();
  	}
    else if(argv[1][0]=='f')
    {//startin garbler p1/p2 assign by p3
      printf("Stating Evaluator 2..\n");
      id=3; //denoting P3
  		evaluator2();
  	}
  	else if(argv[1][0]=='g')
    {//startin garbler p1/p2 assign by p3
      printf("Stating Garbler..\n");
  		garbler();
  	}
  	else
      printf("\npass arguments evaluator/garbler  Eg: ./4pc_god e \n e - evaluator1\n f - evaluator2\n g - garbler1or2\n");

    //Timing prints
    printf("Computation time : %fms\nNetwork time : %fms\nTotal time : %fms\n",comp_time,network_time,comp_time+network_time);
    printf("Send %f bytes\tReceived : %f bytes\n",send_bytes,recv_bytes);
    printf("Send %f KB\tReceived : %f KB\n",send_bytes/1024,recv_bytes/1024);

  	return 0;

}
