#include "../primitives/primitives.h"
#include "../primitives/socket.h"

//varies from circuit to circuits
#define INPUT_4M 512
int blocks_in_one_round = MAX_PAYLOAD_SIZE/sizeof(block);
int sha256_in_one_round = blocks_in_one_round/2;

#define EVENT_ACK_OK 54
#define EVENT_INIT_CLIENT 55
#define EVENT_TTP_INIT 56

#define GC_FILE "circuits/sha_256.txt"
// #define DEBUG

//time calculations
double comp_time = 0, network_time = 0;
double wait_time = 0;

//network bytes
double send_bytes = 0, recv_bytes = 0, broadcast_bytes = 0;
//Trusted third party mode
#define ALICE_TTP 0
#define BOB_TTP 1
#define CLEVE_TTP 2
int ttp_id;//who is the TTP

bool conflict_flag=0;

//Mutex variables for thread syncronization
mutex commit_check_mtx;
mutex decom_check_mtx;
mutex hash_check_mtx;
mutex eval_ready_mtx;
mutex eval_complete;
mutex b_check_mtx;
mutex ttp_mode;
mutex comp_time_mtx;

//Global variables used by both threads
int soc_id[3];//0-Alice , 1-Bob , 2-Cleve
int id;
garble_circuit gc;
void* commit_ip[2];//input wires
void* gc_hash[2];

bool b[INPUT_4M];
bool inputs[INPUT_4M];
bool decomm[INPUT_4M];
block *extractedLabels;
block *computedOutputMap;
bool *outputVals;


int other_garbler_handler(int s_fd);
/*########################
####GARBLER ALICE & BOB###
########################*/
//garbler clients G1 & G2
int garbler(char *ip){
  sockaddr client_addr;
  socklen_t addr_size = sizeof(client_addr);
  clock_t time_beg, time_end;

  u_char buffer[MAX_PAYLOAD_SIZE];

  int server_fd,i,j;
  commit_check_mtx.lock();
  hash_check_mtx.lock();
  eval_complete.lock();

  //Connecting to Evaluator==============================================
  soc_id[2] = socket_connect(ip,SERVER_PORT);
    //dummy recv for exact network_time
    recv(soc_id[2],buffer,1,0);
    time_beg = clock();
  recv(soc_id[2],buffer,MAX_PAYLOAD_SIZE,0);
    time_end = clock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    recv_bytes+=2+INPUT_4M/2;

    time_beg = clock();//computatipn
  if(buffer[1]=='A'){
    cout<<"I\'m Alice\n";
    id = 0;
    //sampling Alice's inputs
    for (i = 0; i < INPUT_4M/4; ++i) {
            inputs[i]= rand() % 2;
    }
    //Copying evaluator's input
    memcpy(inputs+INPUT_4M/2, buffer+2, sizeof(bool) * INPUT_4M/4);
  }
  else if(buffer[1]=='B'){
    cout<<"I\'m Bob\n";
    id = 1;
    //Sampling bob's input
    for (i = INPUT_4M/4; i < INPUT_4M/2; ++i){
            inputs[i]= rand() % 2;
    }
    //Copying evaluator's input
    memcpy(inputs+((3*INPUT_4M)/4), buffer+2, sizeof(bool) * INPUT_4M/4);
  }
  else{
    cout<<"Unknown paty\n";
    exit(0);
  }

  //Input commitment checking==============================================
  if(verify_commitInputs(buffer+2+( sizeof(bool)*INPUT_4M/4 ), buffer+2, INPUT_4M/4,NULL,COMMIT_SCHEME_SHA256)==false){
    printf("Input commitment varification failed\nsetting TTP mode flags\n");
    conflict_flag = 1;
    ttp_id = 1-id;//other garbler
  }
  else{
    // printf("Input commitment varified successfully");
  }

  //Sharing Seed and randomness============================================================
  u_char b_array[INPUT_4M/8];//INPUT_4M/8 for efficiency
	block seed;
  //act as server and send randomness to id==1
  if(id==0){
    server_fd = socket_bind_listen(ip,SERVER_PORT2);
    if(server_fd<0){
      exit(0);
    }
    if((soc_id[1-id]= accept(server_fd,(sockaddr*)(&client_addr) ,&addr_size))<0){
        cout<<"accept failed\n";
        exit(0);
    }
    //Commitment mismatch setting==========================================
    if(conflict_flag == 1){//TTP establishing
      buffer[0] = EVENT_TTP_INIT;
      memcpy(buffer+1,&ttp_id,sizeof(int));
      broadcast(soc_id[1-id], soc_id[2], buffer, MAX_PAYLOAD_SIZE, 0);
      broadcast_bytes+=(1+sizeof(int));
      ttp_mode.unlock();//resume the ttp_execution thread active.
      eval_complete.lock();//wait till evaluation completes.
      eval_complete.unlock();
      return 0;
    }
    //generating randomness
    randomGen(b_array,INPUT_4M/8);
    seed = garble_seed(NULL);

    buffer[0] = EVENT_ACK_OK;
    memcpy(buffer+1,&seed,sizeof(block));
    memcpy(buffer+sizeof(block)+1,b_array,INPUT_4M/8);
      // time_beg = clock();
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;

      send(soc_id[1-id],buffer,1,0);
      time_beg = clock();
    send(soc_id[1-id],buffer,MAX_PAYLOAD_SIZE,0);

    //this recv is for checking weather Bob had an issue
    recv(soc_id[1-id],buffer,MAX_PAYLOAD_SIZE,0);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      send_bytes+=1+sizeof(block)+INPUT_4M/8;
      recv_bytes+=1+sizeof(int);
    if(buffer[0]==EVENT_TTP_INIT){
      send(soc_id[2],buffer,MAX_PAYLOAD_SIZE,0);//informing evaluators other thread
      send_bytes+=1+sizeof(int);
      memcpy(&ttp_id,buffer+1,sizeof(int));
      printf("Commitment mis match detected by Bob\n TTP is %d\n",ttp_id);
      ttp_mode.unlock();
      eval_complete.lock();//wait till evaluation completes.
      eval_complete.unlock();
      return 0;
    }
    time_beg = clock();
  }
  else{//receive randomness
    soc_id[1-id] = socket_connect(ip,SERVER_PORT2);
      time_end = clock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;

      recv(soc_id[1-id],buffer,1,0);
      time_beg = clock();
    recv(soc_id[1-id],buffer,MAX_PAYLOAD_SIZE,0);

    if(buffer[0]==EVENT_TTP_INIT){//Alice detected mismatch
      send(soc_id[2],buffer,MAX_PAYLOAD_SIZE,0);//informing evaluators other thread
        time_end = clock();
        network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
        send_bytes+=1+sizeof(int);
      memcpy(&ttp_id,buffer+1,sizeof(int));
      // printf("Commitment mis match detected by Alice\n TTP is %d\n",ttp_id);
      ttp_mode.unlock();
      eval_complete.lock();//wait till evaluation completes.
      eval_complete.unlock();
      return 0;
    }else if(conflict_flag == 1){//TTP establishing
      printf("Commitment mis match detected by Bob\n TTP is %d\n",ttp_id);
      buffer[0] = EVENT_TTP_INIT;
      memcpy(buffer+1,&ttp_id,sizeof(int));
      broadcast(soc_id[1-id], soc_id[2], buffer, MAX_PAYLOAD_SIZE, 0);
      broadcast_bytes += 1;
      ttp_mode.unlock();
      eval_complete.lock();//wait till evaluation completes.
      eval_complete.unlock();
      return 0;
    }

    buffer[0]=EVENT_ACK_OK;
    send(soc_id[1-id],buffer,MAX_PAYLOAD_SIZE,0);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      send_bytes+=1;
      recv_bytes += 1+sizeof(block)+INPUT_4M/8;
      time_beg = clock();

    memcpy(&seed,buffer+1,sizeof(block));
    memcpy(b_array,buffer+1+sizeof(block),INPUT_4M/8);
    seed = garble_seed(&seed);

  }
  //Shared Randomness----------------------------------------------------


  //Sampling b===========================================================
  //random b values for commitment
  for(i=0;i<INPUT_4M/8;++i){
    for(j=0;j<8;++j){
      b[i*8+j] = (b_array[i]>>j)& 1;
    }
  }

  //Sending b values of Evaluator===============================================
  buffer[0]=EVENT_ACK_OK;
  memcpy(buffer+1, b+INPUT_4M/2,sizeof(bool)*INPUT_4M/2);
  time_end = clock();
  comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;

    thread g_other(other_garbler_handler,soc_id[1-id]);

    //Dummy Sent 1 byte
    send(soc_id[2],buffer,1,0);
    time_beg = clock();
  send(soc_id[2],buffer,sizeof(bool)*INPUT_4M/2+1,0);
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      send_bytes+=sizeof(bool)*INPUT_4M/2+1;
    comp_time_mtx.unlock();
  //Sent b values to the evaluator----------------------------------------------

    time_beg = clock();//time comp

  //Garbling==============================================================
  block *inputLabels = garble_allocate_blocks(2 * gc.n);
  block *outputMap = garble_allocate_blocks(2 * gc.m);
  block *extractedLabels = garble_allocate_blocks(gc.n);
  if (garble_garble(&gc, NULL, outputMap) == GARBLE_ERR) {
      fprintf(stderr, "garble failed\n");
      return -1;
  }
  #ifdef DEBUG
    printf("Garbled gates\n");
  #endif
  //Garbled----------------------------------------------------------------

  memcpy(inputLabels, gc.wires, 2 * gc.n * sizeof(block));
  u_char hash1[SHA256_DIGEST_LENGTH];
  garble_hash(&gc, hash1);
  gc_hash[id] = hash1;
  hash_check_mtx.unlock();
  #ifdef DEBUG
    printf("Hash Computed\n");
  #endif

  //First half of circuit inputs are divided between A and B. Remaining half belong to Carol
  size_t mid = gc.n/2;
  garble_extract_labels1(extractedLabels, inputLabels, inputs, gc.n);

  //Committing on 4m labels====================================================
  char commit_msg[gc.n*2][SHA256_DIGEST_LENGTH];

  i=0;
  while(i<gc.n){
      commit(&(commit_msg[2*i][0]),gc.wires[2*i+b[i]],NULL, COMMIT_SCHEME_SHA256);
      commit(&(commit_msg[2*i+1][0]),gc.wires[2*i+1-b[i]],NULL, COMMIT_SCHEME_SHA256);
      ++i;
  }
  commit_ip[id] = commit_msg;
  commit_check_mtx.unlock();
  #ifdef DEBUG
    printf("Committed to wires\n");
  #endif
  //Committed to 4m wire labels-------------------------------------------------

  //decom info
  bool decom[INPUT_4M];
  for (int i = 0; i < INPUT_4M; ++i){
      decom[i] = (inputs[i] + b[i]) % 2;
  }

  //Sending Cs==================================================================
  //sending comitments for input wires.
  int no_of_rounds = (gc.n*2/sha256_in_one_round);
  int blocks_in_last_round = gc.n*2 %blocks_in_one_round;

    time_end = clock();
    comp_time_mtx.lock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    comp_time_mtx.unlock();

  #ifdef DEBUG
    printf("Sending commitments...\n");
  #endif
    //dummy broadcast (for timing calculations)
    broadcast(soc_id[1-id],soc_id[2],buffer,1,0);
    // send(soc_id[2],buffer,1,0);
    time_beg = clock();
  for(j=0;j< no_of_rounds;++j){
      memcpy(buffer,&commit_msg[j*sha256_in_one_round],sha256_in_one_round*SHA256_DIGEST_LENGTH);
      // send(soc_id[2],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
      broadcast(soc_id[1-id],soc_id[2],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
  }//sending last round
  memcpy(buffer,&commit_msg[j*sha256_in_one_round],blocks_in_last_round*SHA256_DIGEST_LENGTH);
  broadcast(soc_id[1-id],soc_id[2],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);
  // send(soc_id[2],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      broadcast_bytes += gc.n*2*SHA256_DIGEST_LENGTH;
    comp_time_mtx.unlock();

  #ifdef DEBUG
    printf("Sent commitments!\n");
  #endif
  //Sent Cs----------------------------------------------------------------------

  //Sending Hash==================================================================
  #ifdef DEBUG
    printf("Sending hash...\n");
  #endif
  memcpy(buffer,hash1,SHA256_DIGEST_LENGTH);
    //Dummy Sent 1 byte
    send(soc_id[2],buffer,1,0);
    time_beg = clock();
  send(soc_id[2],buffer,SHA256_DIGEST_LENGTH,0);

  #ifdef DEBUG
    printf("Sent hash!\n");
  #endif
  //Sent Hash---------------------------------------------------------------------

   //send output_perms
  memcpy(buffer,gc.output_perms,sizeof(bool)*gc.m);
  send(soc_id[2],buffer,sizeof(bool)*gc.m,0);
    time_end = clock();
    comp_time_mtx.lock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    send_bytes+=sizeof(bool)*gc.m+SHA256_DIGEST_LENGTH;
    comp_time_mtx.unlock();

  //Sending GC===================================================================
  int size_of_table = (gc.q - gc.nxors);
  no_of_rounds = (size_of_table/blocks_in_one_round);
  blocks_in_last_round = size_of_table %blocks_in_one_round;

  #ifdef DEBUG
    printf("Sending GC...\n");
  #endif
    broadcast(soc_id[1-id],soc_id[2],buffer,1,0);
    time_beg = clock();
  for(j=0;j<no_of_rounds;++j){
    memcpy(buffer,gc.table+id*size_of_table+j*blocks_in_one_round,blocks_in_one_round*sizeof(block));
    broadcast(soc_id[1-id],soc_id[2],buffer,blocks_in_one_round*sizeof(block),0);
  }
  memcpy(buffer,gc.table+id*size_of_table+j*blocks_in_one_round,blocks_in_last_round*sizeof(block));
  broadcast(soc_id[1-id],soc_id[2],buffer,blocks_in_last_round*sizeof(block),0);
    time_end = clock();
    comp_time_mtx.lock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    broadcast_bytes+=size_of_table*sizeof(block);
    comp_time_mtx.unlock();

  //Sent GC-----------------------------------------------------------------------

  g_other.join();//other thread will varify the broadcast
  if(conflict_flag==1){
    buffer[0] = EVENT_TTP_INIT;
    memcpy(buffer+1,&ttp_id,sizeof(int));
      //dummy byte sent for timing calculations.
      send(soc_id[2], buffer, 1, 0);
      time_beg = clock();
    send(soc_id[2], buffer, sizeof(bool) * INPUT_4M, 0);
      time_end = clock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      send_bytes+=sizeof(int)+1;

    ttp_mode.unlock();
    eval_complete.lock();//wait till evaluation completes.
    eval_complete.unlock();
    return 0;
  }
  //Send Decommitments============================================================
  #ifdef DEBUG
    printf("Senting Decomitment info!\n");
  #endif

    //Dummy sent for timing
    send(soc_id[2], buffer, 1, 0);
    time_beg = clock();
  //Garbler's index of decommitment
  memcpy(buffer,decom, sizeof(bool) * INPUT_4M);
  send(soc_id[2], buffer, sizeof(bool) * INPUT_4M, 0);
    time_end = clock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    send_bytes+=sizeof(bool) *INPUT_4M;

  //Garblers labels for decommit
    //Dummy sent for timing
    send(soc_id[2], buffer, 1, 0);
    time_beg = clock();
  memcpy(buffer, extractedLabels, sizeof(block) * gc.n);
  send(soc_id[2], buffer, sizeof(block) * gc.n,0);
  //Sent Decommitments-------------------------------------------------------------
    time_end = clock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    send_bytes += sizeof(block) * gc.n;

  //receving Y from evaluator.===============================================
    //Dummy sent for timing
    recv(soc_id[2], buffer, 1, 0);
    time_beg = clock();
  recv(soc_id[2], buffer, sizeof(block) * gc.m, 0);
    time_end = clock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    recv_bytes += sizeof(block) * gc.m;

  if(buffer[0]==EVENT_TTP_INIT){
    memcpy(&ttp_id,buffer+1,sizeof(int));
    ttp_mode.unlock();
    eval_complete.lock();//wait till evaluation completes.
    eval_complete.unlock();
    return 0;
  }

    time_beg = clock();

  block *computedOutputMap = garble_allocate_blocks(gc.m);
  bool *outputVals = (bool*) calloc(gc.m, sizeof(bool));

  memcpy(computedOutputMap,buffer,sizeof(block) * gc.m);

  #ifdef DEBUG
    printf("receved Y from evaluator\no/p : ");
  #endif

	assert(garble_map_outputs(outputMap, computedOutputMap, outputVals, gc.m) == GARBLE_OK);
  // for(i=0;i<gc.m;i++){
  //   cout<<outputVals[i]<<" ";
  // }

    time_end = clock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;

  printf("\nEvaluated output successfully\n");
    send(soc_id[2],buffer,1,0);
    time_beg = clock();
  memcpy(buffer, outputMap, sizeof(block)*2*gc.m);
  send(soc_id[2], buffer, sizeof(block) * 2 * gc.m,0);
    time_end = clock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    send_bytes += sizeof(block) * 2 * gc.m;
  printf("Computation time : %f\nNetwork time : %f\n",comp_time,network_time);
  printf("Send %f bytes\tReceived : %f bytes\tBroadcasted : %f bytes\n",send_bytes,recv_bytes,broadcast_bytes);
  printf("Send %f KB\tReceived : %f KB\tBroadcasted : %f KB\n",send_bytes/1024,recv_bytes/1024,broadcast_bytes/1024);
}

/*############################
#### OTHER GARBLER HANDLER ###
##############################*/
//thread function to handle broadcast from other garbler
int other_garbler_handler(int s_fd){
  clock_t time_beg, time_end;
  int i,j;
  u_char buffer[MAX_PAYLOAD_SIZE];

  u_char commit_msg_other[gc.n*2][SHA256_DIGEST_LENGTH];
  int no_of_rounds = (gc.n*2/sha256_in_one_round);
  int blocks_in_last_round = gc.n*2 %blocks_in_one_round;
    //dummy send (for timing calculations)
    recv(s_fd,buffer,1,0);
    time_beg = clock();
  for(j=0;j< no_of_rounds;++j){
      recv(s_fd,buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
      memcpy(&commit_msg_other[j*sha256_in_one_round],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH);
  }//sending last round
  recv(s_fd,buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);
  memcpy(&commit_msg_other[j*sha256_in_one_round],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH);
    time_end = clock();
    comp_time_mtx.lock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    recv_bytes += gc.n*2*SHA256_DIGEST_LENGTH;
    comp_time_mtx.unlock();

  //cheching I/P commitment broadcasted is equal
  commit_check_mtx.lock();

    time_beg = clock();

  if(memcmp(commit_msg_other,commit_ip[id],gc.n*2*SHA256_DIGEST_LENGTH) != 0){
    cout<<"commitment for G1&G2 are not equal\n setting conflict flag...\n";
    conflict_flag = 1;
    ttp_id = 3;
  }
  // cout<<"####OGT: commitments are equal, \n";
    time_end = clock();
    comp_time_mtx.lock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    comp_time_mtx.unlock();
  commit_check_mtx.unlock();


  //receiving the garble circuit================================================
  int size_of_table = (gc.q - gc.nxors);
  no_of_rounds = (size_of_table/blocks_in_one_round);
  blocks_in_last_round = size_of_table %blocks_in_one_round;
    //dummy send (for timing calculations)
    recv(s_fd,buffer,1,0);
    time_beg = clock();
  for(j=0;j<no_of_rounds;++j){
    recv(s_fd,buffer,blocks_in_one_round*sizeof(block),0);
    memcpy(gc.table+(1-id)*size_of_table+j*blocks_in_one_round,buffer,blocks_in_one_round*sizeof(block));
  }
  recv(s_fd,buffer,blocks_in_last_round*sizeof(block),0);
  memcpy(gc.table+(1-id)*size_of_table+j*blocks_in_one_round,buffer,blocks_in_last_round*sizeof(block));
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      recv_bytes += size_of_table*sizeof(block);
    comp_time_mtx.unlock();


    hash_check_mtx.lock();
          time_beg = clock();
        // cout<<"Comparing hashes\n";
        u_char hash_calc[SHA256_DIGEST_LENGTH]; //calculating hash of received GC
        garble_hash(&gc, hash_calc);
        // printf("%s\n", hash_calc);

        if(memcmp(hash_calc,gc_hash[id],SHA256_DIGEST_LENGTH)!=0){
          cout<<"in OGT:hash is not equal to the GC\n";
          conflict_flag = 1;
          ttp_id = 2;
        }
        else{
          cout<<"in OGT: Hashes are equal!!!\n";
        }
          time_end = clock();
          comp_time_mtx.lock();
          comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
          comp_time_mtx.unlock();

     hash_check_mtx.unlock();

}
/*######################
#### GARBLER HANDLER ###
######################*/
//thread function to handle the client garblers
int garble_handler(int id){
  u_char buffer[MAX_PAYLOAD_SIZE];
  int i,j;
  clock_t time_beg, time_end;
  u_char ip_msg_hash[SHA256_DIGEST_LENGTH];
  u_char ipother_msg_hash[SHA256_DIGEST_LENGTH];

  time_beg = clock();//computatipn

  //Initializing clients
  buffer[0] = EVENT_INIT_CLIENT;

  if(id == 0){
    #ifdef DEBUG
      cout<<"Handling Alice..\nsending initialization msg to Alice\n";
    #endif
    buffer[1]= 'A';
    memcpy(buffer+2, inputs+INPUT_4M/2, sizeof(bool) * INPUT_4M/2);
    // memcpy(buffer+2+INPUT_4M/4,inputs+((3*INPUT_4M)/4), sizeof(bool) * INPUT_4M/4);
    commit_check_mtx.lock();
    hash_check_mtx.lock();
    eval_ready_mtx.lock();
    eval_complete.lock();
    b_check_mtx.lock();
    decom_check_mtx.lock();
  }
  else if(id == 1){
    #ifdef DEBUG
      cout<<"Handling Bob..\nsending initialization msg to Bob\n";
    #endif
    buffer[1]= 'B';
    memcpy(buffer+2, inputs+((3*INPUT_4M)/4), sizeof(bool) * INPUT_4M/2);
    // memcpy(buffer+2+INPUT_4M/4, inputs+INPUT_4M/2, sizeof(bool) * INPUT_4M/4);
  }
  else
  {
    cout<<"Unknown paty\n";
    exit(0);
  }
  //commiting the inputwires sending
  commitInputs(ip_msg_hash,buffer+2, INPUT_4M/4, NULL, COMMIT_SCHEME_SHA256);
  commitInputs(ipother_msg_hash, buffer+2+INPUT_4M/4, INPUT_4M/4, NULL, COMMIT_SCHEME_SHA256);

  memcpy(buffer+2+INPUT_4M/4, ip_msg_hash , SHA256_DIGEST_LENGTH);
  memcpy(buffer+2+INPUT_4M/4+SHA256_DIGEST_LENGTH, ipother_msg_hash , SHA256_DIGEST_LENGTH);

    time_end = clock();
    comp_time_mtx.lock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    comp_time_mtx.unlock();

  //testing changing inputs Evaluator is corrupt
  // if(id==1) buffer[40]=55;//bob will detect the error
    //dummy recv for exact network_time
    send(soc_id[id],buffer,1,0);
    time_beg = clock();
  send(soc_id[id],buffer,MAX_PAYLOAD_SIZE,0);
    time_end = clock();
    comp_time_mtx.lock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    send_bytes += 2+INPUT_4M/2;
    comp_time_mtx.unlock();

  //Sending initialization and inputs of evaluator done!!=======================

    recv(soc_id[id],buffer, 1, 0);
    time_beg = clock();
  recv(soc_id[id],buffer, sizeof(bool)*INPUT_4M/2 +1, 0);
    time_end = clock();
    comp_time_mtx.lock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    recv_bytes += sizeof(bool)*INPUT_4M/2+1;
    comp_time_mtx.unlock();

  //check if both Alice and Bob send mismatch
  if(buffer[0]==EVENT_TTP_INIT){
    memcpy(&ttp_id,buffer+1,sizeof(int));
    ttp_mode.unlock();
    eval_complete.lock();//wait till evaluation completes.
    eval_complete.unlock();
    return 0;
  }

  //Receiving b values==========================================================
  if(id==0)
    memcpy(b,buffer+1,sizeof(bool)*INPUT_4M/2);
  else
    memcpy(b+INPUT_4M/2,buffer+1,sizeof(bool)*INPUT_4M/2);
  #ifdef DEBUG
    printf("Received b values\n");
  #endif

  //Comparing b values==========================================================
  if(id==1){
    b_check_mtx.lock();

      time_beg = clock();//computatipn

    if(memcmp(b,b+INPUT_4M/2,sizeof(bool)*INPUT_4M/2)!=0){
      printf("received b values are not equal\t setting conflict flag...\n");
      // for(int i=0;i<INPUT_4M;i++){
      //   cout<<b[i]<<" ";
      // }
      conflict_flag=1;
      ttp_id = 0;
    }
    // printf("received b values are equal\n");

      time_end = clock();
      comp_time_mtx.lock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      comp_time_mtx.unlock();

    b_check_mtx.unlock();
  }
  else{
    b_check_mtx.unlock();
  }

  //receving commitments========================================================
  u_char commit_msg[gc.n*2][SHA256_DIGEST_LENGTH];
  int no_of_rounds = (gc.n*2/sha256_in_one_round);
  int blocks_in_last_round = gc.n*2 %blocks_in_one_round;

    //dummy recv (for timing calculations)
    recv(soc_id[id],buffer,1,0);
    time_beg = clock();
  for(j=0;j< no_of_rounds;++j){
      recv(soc_id[id],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
      memcpy(&commit_msg[j*sha256_in_one_round],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH);
  }//sending last round
  recv(soc_id[id],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);
  memcpy(&commit_msg[j*sha256_in_one_round],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH);
    time_end = clock();
    comp_time_mtx.lock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    recv_bytes += gc.n*2*SHA256_DIGEST_LENGTH;
    comp_time_mtx.unlock();
  commit_ip[id] = commit_msg;
  #ifdef DEBUG
    printf("Received All commitments from %d!\n",id);
  #endif
  //receved all commitments-----------------------------------------------------

  //varification of commitment==================================================
  if(id==1){//Bob_hanler will varify
    commit_check_mtx.lock();
      time_beg = clock();//computatipn
    if(memcmp(commit_ip[0],commit_ip[1],gc.n*2*SHA256_DIGEST_LENGTH) != 0){
      cout<<"commitment for G1&G2 are not equal\n setting conflict flag...\n";
      conflict_flag = 1;
      ttp_id = 0;
    }
      time_end = clock();
      comp_time_mtx.lock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      comp_time_mtx.unlock();
    commit_check_mtx.unlock();
  }
  else{
    commit_check_mtx.unlock();
  }

  //recieve hash of GC=========================================================
  u_char hash[SHA256_DIGEST_LENGTH];

    recv(soc_id[id],buffer, 1, 0);
    time_beg = clock();
  recv(soc_id[id],buffer,SHA256_DIGEST_LENGTH,0);

  memcpy(hash,buffer,SHA256_DIGEST_LENGTH);
  gc_hash[id] = hash;

  #ifdef DEBUG
    printf("Received Hash of GC\n");
  #endif
  recv(soc_id[id],buffer,sizeof(bool)*gc.m,0);
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      recv_bytes += SHA256_DIGEST_LENGTH+ sizeof(bool)*gc.m;
    comp_time_mtx.unlock();


    time_beg = clock();//computatipn

  gc.output_perms = (bool *)calloc(gc.m, sizeof(bool));
  memcpy(gc.output_perms,buffer,sizeof(bool)*gc.m);
  //receiving the garble circuit================================================
  int size_of_table = (gc.q - gc.nxors);
  no_of_rounds = (size_of_table/blocks_in_one_round);
  blocks_in_last_round = size_of_table %blocks_in_one_round;

    time_end = clock();
    comp_time_mtx.lock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    comp_time_mtx.unlock();

    //dummy send (for timing calculations)
    recv(soc_id[id],buffer,1,0);
    time_beg = clock();
  for(j=0;j<no_of_rounds;++j){
    recv(soc_id[id],buffer,blocks_in_one_round*sizeof(block),0);
    memcpy(gc.table+id*size_of_table+j*blocks_in_one_round,buffer,blocks_in_one_round*sizeof(block));
  }
  recv(soc_id[id],buffer,blocks_in_last_round*sizeof(block),0);
  memcpy(gc.table+id*size_of_table+j*blocks_in_one_round,buffer,blocks_in_last_round*sizeof(block));
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      recv_bytes += size_of_table*sizeof(block);
    comp_time_mtx.unlock();

  #ifdef DEBUG
    printf("Received GC!\n");
  #endif

  //checking hash of GC and received hashes=====================================
  if(id==1){
    hash_check_mtx.lock();
        time_beg = clock();//computatipn
      u_char hash_calc[SHA256_DIGEST_LENGTH]; //calculating hash of received GC
      garble_hash(&gc, hash_calc);
      // printf("%s\n", hash_calc);

      if(memcmp(hash_calc,gc_hash[0],SHA256_DIGEST_LENGTH)!=0){
        cout<<"hash is not equal to the GC\n";
        conflict_flag = 1;
        ttp_id = 0;
      }
      else if(memcmp(gc_hash[0],gc_hash[1],SHA256_DIGEST_LENGTH)!=0){
        cout<<"hashes is not equal to each other\n";
        conflict_flag = 1;
        ttp_id = 0;
      }
      else{
        // cout<<"Hashes are equal!!!\n";
      }
        time_end = clock();
        comp_time_mtx.lock();
        comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
        comp_time_mtx.unlock();
   hash_check_mtx.unlock();
  }
  else{
    hash_check_mtx.unlock();
  }

  //recive decomitments=======git==================================================
    recv(soc_id[id],buffer, 1, 0);
    time_beg = clock();
  recv(soc_id[id], buffer, sizeof(bool) * INPUT_4M, 0);
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      recv_bytes += sizeof(bool) * INPUT_4M;
    comp_time_mtx.unlock();


    time_beg = clock();//computatipn
  if(buffer[0]==EVENT_TTP_INIT){
      memcpy(&ttp_id,buffer+1,sizeof(int));
      ttp_mode.unlock();
      eval_complete.lock();//wait till evaluation completes.
      eval_complete.unlock();
      return 0;
  }
  memcpy(decomm+(id*INPUT_4M/4), buffer+(id*INPUT_4M/4), sizeof(bool) * INPUT_4M/4);
  for (int i = INPUT_4M/2; i < INPUT_4M; ++i){
      decomm[i] = (inputs[i] + b[i]) % 2;
  }

    time_end = clock();
    comp_time_mtx.lock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    comp_time_mtx.unlock();

  #ifdef DEBUG
    printf("received decomitments\n");
  #endif

  //Receiving Garblers labels for decommitment====================================
    recv(soc_id[id],buffer, 1, 0);
    time_beg = clock();
  recv(soc_id[id], buffer, sizeof(block) * gc.n,0);
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      recv_bytes +=sizeof(block) * gc.n;
    comp_time_mtx.unlock();

    time_beg = clock();//computatipn
  if(id==0){
    memcpy(extractedLabels, buffer, sizeof(block) * gc.n/4);
    memcpy(extractedLabels+gc.n/2, buffer+(gc.n/2)*sizeof(block), sizeof(block) * gc.n/4);
  }
  else{
    memcpy(extractedLabels+(gc.n/4), buffer+(gc.n/4)*sizeof(block), sizeof(block) * gc.n/4);
    memcpy(extractedLabels+(gc.n/2+gc.n/4), buffer+(gc.n/2+gc.n/4)*sizeof(block), sizeof(block) * gc.n/4);
  }
    time_end = clock();
    comp_time_mtx.lock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
    comp_time_mtx.unlock();

  #ifdef DEBUG
    printf("received extractedLabels\n");
  #endif

  //Verify Decommitments===============================================
  if(id==1){
    decom_check_mtx.lock();
      time_beg = clock();//computatipn
    for (i = 0; i < INPUT_4M; ++i){
       if(verify_commit((char*)&commit_msg[2*i+decomm[i]][0], extractedLabels[i], NULL, COMMIT_SCHEME_SHA256) == false){
         printf("Commitment varification(at %d) failed\n",i);
         if(i<128 || (i>=256 && i<384))
            ttp_id = 1; //P1 is corrupt
         else
            ttp_id = 0; //P2 is corrupt
        conflict_flag = 1;
       }
     }
       time_end = clock();
       comp_time_mtx.lock();
       comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
       comp_time_mtx.unlock();
    decom_check_mtx.unlock();
  }else{
    decom_check_mtx.unlock();
  }
  #ifdef DEBUG
    printf("Decomitment varification done\n");
  #endif
  if(conflict_flag == 1){
    buffer[0] = EVENT_TTP_INIT;
    memcpy(buffer+1,&ttp_id,sizeof(int));
    send(soc_id[id], buffer, gc.m*sizeof(block), 0);
    send_bytes += 1+ sizeof(int);
    ttp_mode.unlock();
    eval_complete.lock();//wait till evaluation completes.
    eval_complete.unlock();
    return 0;
  }
  //evaluating  =========================================================
  #ifdef DEBUG
    printf("Evaluation started\n");
  #endif
  if(id==1){
    eval_ready_mtx.lock();
      time_beg = clock();//computatipn
    if(garble_eval(&gc, extractedLabels, computedOutputMap, outputVals)==GARBLE_ERR){
      printf("Evaluation failed..!\nAbourting..\n");
      exit(0);
    }

      time_end = clock();
      comp_time_mtx.lock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      comp_time_mtx.unlock();

    eval_ready_mtx.unlock();
    eval_complete.unlock();
  }else{
    eval_ready_mtx.unlock();
  }

  eval_complete.lock();//waiting for other handler to complete
  eval_complete.unlock();


  //Sent Y to garblers
    #ifdef DEBUG
    printf("\nSending Y(computedOutputMap) to garblers\n");
    #endif
  block *outputMap = garble_allocate_blocks(gc.m*2);
  memcpy(buffer,computedOutputMap,gc.m*sizeof(block));

    send(soc_id[id],buffer, 1, 0);
    time_beg = clock();
  send(soc_id[id], buffer, gc.m*sizeof(block), 0);
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      send_bytes += gc.m*sizeof(block);
    comp_time_mtx.unlock();

  //Receving the decoding information
    recv(soc_id[id],buffer,1,0);
    time_beg = clock();
  recv(soc_id[id], buffer, gc.m*2*sizeof(block), 0);
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
      recv_bytes += gc.m*2*sizeof(block);
    comp_time_mtx.unlock();

  if(id==1){
      time_beg = clock();//Computation_time
    memcpy(outputMap,buffer, gc.m*2*sizeof(block));
    assert(garble_map_outputs(outputMap, computedOutputMap, outputVals, gc.m) == GARBLE_OK);
    // for(i=0;i<gc.m;i++){
    //   cout<<outputVals[i]<<" ";
    // }
      time_end = clock();
        comp_time_mtx.lock();
        comp_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
        comp_time_mtx.unlock();
    printf("\nEvaluated output successfully\n");
    printf("Computation time : %f\nNetwork time : %f\n",comp_time,network_time);
    // printf("P1\t%f\t%f\n",comp_time,network_time);
    printf("Send %f bytes\tReceived : %f bytes\tBroadcasted : %f bytes\n",send_bytes,recv_bytes,broadcast_bytes);
    printf("Send %f KB\tReceived : %f KB\tBroadcasted : %f KB\n",send_bytes/1024,recv_bytes/1024,broadcast_bytes/1024);

  }
}

//Trusted thirdparty mode, when some parties behave malious.
void ttp_execution(){
  clock_t time_beg, time_end;
	ttp_mode.lock();//wait till this lock is released
  u_char buffer[MAX_PAYLOAD_SIZE];
  u_char buff[MAX_PAYLOAD_SIZE];
  //bool inputs[MAX_PAYLOAD_SIZE];
  int flag=0;
	switch(ttp_id){
		case ALICE_TTP:
			{
			   printf("Alice is the TTP :)\n");
			   //behave accordingly id=0,id=1,id=2
         if(id==0){
            recv(soc_id[2], buffer, sizeof(bool)*INPUT_4M/4,0); //get o32
            //copy Alice's inputs. Already done
            if(verify_commitInputs(buff,buffer, INPUT_4M/4, NULL, COMMIT_SCHEME_SHA256)==false){
                printf("Cle sent wrong value\n");
                flag=1;
            }
            else{
                memcpy(inputs+3*INPUT_4M/4,buffer, INPUT_4M/4);
            }
            recv(soc_id[1], buffer, MAX_PAYLOAD_SIZE, 0); //receive from Bob
            memcpy(inputs + INPUT_4M/4, buffer + INPUT_4M/4, INPUT_4M/4);

            if(flag==1){
                if(verify_commitInputs(buff, buffer, INPUT_4M/4, NULL, COMMIT_SCHEME_SHA256)==false){
                    printf("Bob is lying too\n");
                    for (int i = 0; i < INPUT_4M/4; ++i){
                       inputs[3* INPUT_4M/4 + i]= rand()%2; //get default input for P3
                    }
                }
                else{
                    memcpy(inputs+3*INPUT_4M/4,buffer, INPUT_4M/4);
                }
            }

            //compute f(x,y,z)
            broadcast(soc_id[1], soc_id[2], buffer, 256, 0);

         }
         else if(id==1){
            sleep(2);//WHY?
            memcpy(buffer, inputs + 3 * INPUT_4M/4, INPUT_4M);
            send(soc_id[0], buffer, INPUT_4M/4, 0);
            recv(soc_id[0], buffer, 256, 0);
            printf("TTp sent Y\n");
         }
         else{
            memcpy(buffer, inputs + 3* INPUT_4M/4, INPUT_4M);
            send(soc_id[0], buffer, INPUT_4M/4, 0);
            recv(soc_id[0], buffer, 256, 0);

            printf("TTp sent Y\n");
         }
			}
			break;

		case BOB_TTP:
			{
			   printf("Bob is the TTP :)\n");
			   //behave accordingly id=0,id=1,id=2
         if(id==1)
         {
            recv(soc_id[2], buffer, sizeof(bool)*INPUT_4M/4,0); //get o32
            //copy Bob'ss inputs.
            if(verify_commitInputs(buff,buffer, INPUT_4M/4, NULL, COMMIT_SCHEME_SHA256)==false)
            {
                printf("Cle sent wrong value\n");
                flag=1;

            }
            else
            {
                memcpy(inputs+2*INPUT_4M/4,buffer, INPUT_4M/4);
            }


            recv(soc_id[0], buffer, MAX_PAYLOAD_SIZE, 0); //receive from Bob
            memcpy(inputs, buffer + INPUT_4M/4, INPUT_4M/4);

            if(flag==1)
            {
                if(verify_commitInputs(buff, buffer, INPUT_4M/4, NULL, COMMIT_SCHEME_SHA256)==false)
                {
                    printf("Alice is lying too\n");
                    for (int i = 0; i < INPUT_4M/4; ++i)
                    {
                       inputs[2* INPUT_4M/4 + i]= rand()%2; //get default input for P3
                    }
                }
                else
                {
                    memcpy(inputs+2*INPUT_4M/4,buffer, INPUT_4M/4);
                }
            }

            //compute f(x,y,z)
            broadcast(soc_id[0], soc_id[2], buffer, 256, 0);

         }
         else if(id==0)
         {
            sleep(2);
            memcpy(buffer, inputs + 2 * INPUT_4M/4, INPUT_4M);
            send(soc_id[1], buffer, INPUT_4M/4, 0);
            recv(soc_id[1], buffer, 256, 0);

            printf("TTp sent Y\n");
         }
         else
         {
            memcpy(buffer, inputs + 2*INPUT_4M/4, INPUT_4M);
            send(soc_id[1], buffer, INPUT_4M/4, 0);
            recv(soc_id[1], buffer, 256, 0);

            printf("TTp sent Y\n");
         }


			}
			break;

		case CLEVE_TTP:
			{
			   printf("Cleve is the TTP :)\n");
			   //behave accordingly id=0,id=1,id=2

         if(id==2)
         {
            recv(soc_id[0], buffer, INPUT_4M/4, 0);
            memcpy(inputs, buffer, INPUT_4M/4);

            recv(soc_id[1], buffer, INPUT_4M/4, 0);
            memcpy(inputs+INPUT_4M/4, buffer, INPUT_4M/4);

            //compute f(x,y,z)
            broadcast(soc_id[0], soc_id[1], buffer, 256, 0);
         }
         else if(id==0)
         {
            memcpy(buffer, inputs, INPUT_4M);
            send(soc_id[2], buffer, INPUT_4M/4, 0);

            recv(soc_id[2], buffer, INPUT_4M/4, 0);

            printf("Received Y\n");

         }
         else
         {
            memcpy(buffer, inputs + INPUT_4M/4, INPUT_4M);
            send(soc_id[2], buffer, INPUT_4M/4, 0);

            recv(soc_id[2], buffer, INPUT_4M/4, 0);

            printf("Received Y\n");
         }

			}
			break;
		default:
			printf("Unknown behaviour\nAborting...");
			exit(0);
	}
	ttp_mode.unlock();

  //After completing evaluation
  eval_complete.unlock();
}
//P3 server open for connecting P1 & P2
void evaluator(char *ip){
    sockaddr client_addr;
    socklen_t addr_size = sizeof(client_addr);
    int server_fd;

		id=2;//2-Cleve
    soc_id[2] = socket_bind_listen(ip,SERVER_PORT);

    //Sampling inputs for evaluator
    for (size_t i = INPUT_4M/2; i < INPUT_4M; ++i) {
            inputs[i]= rand() % 2;
    }
    //allocating global variables
    gc.table = (block*) calloc(gc.q - gc.nxors,garble_table_size(&gc));
    extractedLabels = garble_allocate_blocks(gc.n);
    computedOutputMap = garble_allocate_blocks(gc.m);
    outputVals = (bool*) calloc(gc.m, sizeof(bool));
    if((soc_id[0] = accept(soc_id[2],(sockaddr*)(&client_addr) ,&addr_size))<0){
      cout<<"accept failed\n";
    }
    //starting Alice_handler
    thread g1 (garble_handler,0);

    if((soc_id[1] = accept(soc_id[2],(sockaddr*)(&client_addr) ,&addr_size))<0){
      cout<<"accept failed\n";
    }
    //Starting Bob_handler
    thread g2 (garble_handler,1);
    #ifdef DEBUG
      cout<<"\nsoc_id for g1(Alice):"<<soc_id[0]<<" ,soc_id for g2(Bob):"<<soc_id[1]<<"\n";
    #endif

    //soft decode and learn the output from
    #ifdef DEBUG
      printf("Eval main waiting for Bob_handler to exit\n");
    #endif
    g2.join();
    g1.join();
}

/* convebtion three parties A,B,C (P1,P2,P3) (Alice,Bob,Cleve).
Cleve is the evaluator, Alice and Bob are the garblers

 ./3pc e 127.0.0.1   -starts evaluvator at ip
 ./3pc g 127.0.0.1   -start garbler evaluator assign either 1/2*/


int main(int argc, char *argv[]){

  	if(argc !=3){
  		printf("\npass arguments evaluator/garbler at ip   Eg: ./3pc e 127.0.0.1\n e - evaluator\n g - garbler\n");
  		exit(0);
  	}

    // loading garbled circuit from file
  	build(&gc,GC_FILE);

    #ifdef DEBUG
      cout<<"gc file read done..\ngc->n,m,q,r,nxor "<<gc.n<<" , "<<gc.m<<" , "<<gc.q<<" , "<<gc.r<<" , "<<gc.nxors<<"\n";
    #endif

  	char *ip = argv[2];

		ttp_mode.lock();
		thread ttp_thread(ttp_execution);

  	if (argv[1][0]=='e')
    {//starting evaluator p3 in MRZ15
      printf("Stating Cleve..\n");
  		evaluator(ip);
  	}
  	else if(argv[1][0]=='g')
    {//startin garbler p1/p2 assign by p3
  		garbler(ip);
  	}
  	else
  		printf("\nInvalid commandline arguments\nChoose evaluator/garbler and ip for communication\nEg: ./3pc e 127.0.0.1\n e - evaluator\n g - garbler\n");

		exit(0);
  	return 0;
}
