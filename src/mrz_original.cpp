#include "../primitives/primitives.h"
#include "../primitives/socket.h"

//varies from circuit to circuits
#define INPUT_4M 256
int blocks_in_one_round = MAX_PAYLOAD_SIZE/sizeof(block);
int sha256_in_one_round = blocks_in_one_round/2;

#define GC_FILE "circuits/aes.txt"
// #define DEBUG

//time calculations
#define CLOCKS_PER_M_SEC 1000
double comp_time = 0, network_time = 0;
double wait_time = 0;

//network bytes
double send_bytes = 0, recv_bytes = 0, broadcast_bytes = 0;

//Mutex variables for thread syncronization
mutex commit_check_mtx;
mutex decom_check_mtx;
mutex hash_check_mtx;
mutex eval_ready_mtx;
mutex eval_complete;
mutex b_check_mtx;
mutex comp_time_mtx;

//Global variables used by both threads
int client_soc[2];
garble_circuit gc;
void* commit_ip[2];
void* gc_hash[2];

bool b[INPUT_4M];
bool inputs[INPUT_4M];
bool decomm[INPUT_4M];
block *extractedLabels;
block *computedOutputMap;
bool *outputVals;

/*########################
####GARBLER ALICE & BOB###
########################*/
//garbler clients G1 & G2
int garbler(char *ip){

  u_char buffer[MAX_PAYLOAD_SIZE];
  int server_fd, id,i,j;
  clock_t time_beg, time_end;

  //Connecting to Evaluator==============================================
  server_fd = socket_connect(ip,SERVER_PORT);

    //dummy send (for exact timing calculations)
    recv(server_fd,buffer,1,0);
    time_beg = clock();
  recv(server_fd,buffer,INPUT_4M/2+3,0);
    time_end = clock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    recv_bytes += INPUT_4M/2+3;

    #ifdef DEBUG
      cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif

    time_beg = clock();//computation time
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

  u_char b_array[INPUT_4M/8];//INPUT_4M/8 for efficiency
	block seed;

  //Sharing Seed============================================================
  //act as server and send randomness to id==1
  if(id==0){
      sockaddr client_addr;
      socklen_t addr_size = sizeof(client_addr);
      int g_server_fd,g_id;

      g_server_fd = socket_bind_listen(ip,SERVER_PORT2);

      if(server_fd<0){
        exit(0);
      }

      if((g_id= accept(g_server_fd,(sockaddr*)(&client_addr) ,&addr_size))<0){
          cout<<"accept failed\n";
          exit(0);
      }
      //generating randomness
      randomGen(b_array,INPUT_4M/8);
      seed = garble_seed(NULL);

      memcpy(buffer,&seed,sizeof(block));
      memcpy(buffer+sizeof(block),b_array,INPUT_4M/8);

        time_end = clock();
        comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

        #ifdef DEBUG
          cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
        #endif

        //dummy send (for exact timing calculations)
        send(g_id,buffer,1,0);
        time_beg = clock();
      send(g_id,buffer,INPUT_4M/8+sizeof(block),0);
        time_end = clock();
        network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
        send_bytes+=sizeof(block)+INPUT_4M/8;

        #ifdef DEBUG
          cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
        #endif

        close(g_server_fd);
        close(g_id);
        time_beg = clock();//computation time
  }
  else{//receive randomness
    int g_server_fd;
    g_server_fd = socket_connect(ip,SERVER_PORT2);

    // time_beg = clock();
    time_end = clock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    #ifdef DEBUG
      cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif

      //dummy send (for exact timing calculations)
      recv(g_server_fd,buffer,1,0);
      time_beg = clock();
    recv(g_server_fd,buffer,INPUT_4M/8+sizeof(block),0);
      time_end = clock();
      network_time = network_time + double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes += sizeof(block)+INPUT_4M/8;

      #ifdef DEBUG
        cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
      #endif

    close(g_server_fd);
      time_beg = clock();//computation time
    memcpy(&seed,buffer,sizeof(block));
    memcpy(b_array,buffer+sizeof(block),INPUT_4M/8);

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
  // Sampled b------------------------------------------------------------

  //Sending b values of Evaluator===============================================
  memcpy(buffer, b+INPUT_4M/2,sizeof(bool)*INPUT_4M/2);
    time_end = clock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    #ifdef DEBUG
      cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif

    //dummy recv (for timing calculations)
    send(server_fd,buffer,1,0);
    time_beg = clock();
  send(server_fd,buffer,sizeof(bool)*INPUT_4M/2,0);
    time_end = clock();
    network_time =network_time + double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    send_bytes += sizeof(bool)*INPUT_4M/2;
  //Sent b values to the evaluator----------------------------------------------

  #ifdef DEBUG
    cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
  #endif

  time_beg = clock();
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
  #ifdef DEBUG
    printf("Hash Computed\n");
  #endif

  //First half of circuit inputs are divided between A and B. Remaining half belong to Carol
  size_t mid = gc.n/2;
  garble_extract_labels1(extractedLabels, inputLabels, inputs, gc.n);

  //Committing on 4m labels====================================================
  char commit_msg[gc.n*2][SHA256_DIGEST_LENGTH];
  commit_ip[id] = commit_msg;

  i=0;
  while(i<gc.n){
      commit(&(commit_msg[2*i][0]),gc.wires[2*i+b[i]],NULL, COMMIT_SCHEME_SHA256);
      commit(&(commit_msg[2*i+1][0]),gc.wires[2*i+1-b[i]],NULL, COMMIT_SCHEME_SHA256);
      ++i;
  }
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
  #ifdef DEBUG
    printf("Sending commitments...\n");
    // printf("no of rounds = %d ; blk_in lst_round %d\n",no_of_rounds,blocks_in_last_round);
  #endif
  // time_beg = clock();
  time_end = clock();
  comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

  #ifdef DEBUG
    cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
  #endif

    //dummy send (for timing calculations)
    send(server_fd,buffer,1,0);
    time_beg = clock();
  // for(j=0;j< gc.n*2;++j){
  //     memcpy(buffer,&commit_msg[j],SHA256_DIGEST_LENGTH);
  //     send(server_fd,buffer,SHA256_DIGEST_LENGTH,0);
  // }
  for(j=0;j< no_of_rounds;++j){
      memcpy(buffer,&commit_msg[j*sha256_in_one_round],sha256_in_one_round*SHA256_DIGEST_LENGTH);
      send(server_fd,buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
  }//sending last round
  memcpy(buffer,&commit_msg[j*sha256_in_one_round],blocks_in_last_round*SHA256_DIGEST_LENGTH);
  send(server_fd,buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);

    time_end = clock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    send_bytes += gc.n*2*SHA256_DIGEST_LENGTH;

    #ifdef DEBUG
      cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif

    // printf("network_time = %d\n",network_time);
  #ifdef DEBUG
    printf("Sent commitments!\n");
  #endif
  //Sent Cs----------------------------------------------------------------------

  //Sending Hash==================================================================
  #ifdef DEBUG
    printf("Sending hash...\n");
  #endif
  int len = strlen((char *)hash1);

    //dummy send (for timing calculations)
    send(server_fd,buffer,1,0);
    time_beg = clock();
  memcpy(buffer,hash1,SHA256_DIGEST_LENGTH);
  send(server_fd,buffer,SHA256_DIGEST_LENGTH,0);
  #ifdef DEBUG
    printf("Sent hash!\n");
  #endif
  //Sent Hash---------------------------------------------------------------------
  //send output_perms
  if(id==1){
    memcpy(buffer,gc.output_perms,sizeof(bool)*gc.m);
    send(server_fd,buffer,sizeof(bool)*gc.m,0);
  }
    time_end = clock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    send_bytes+=sizeof(bool)*gc.m+SHA256_DIGEST_LENGTH;

    #ifdef DEBUG
      cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif

    time_beg = clock();//comp time
  //Sending GC===================================================================
  int size_of_table = (gc.q - gc.nxors);
  no_of_rounds = (size_of_table/blocks_in_one_round);
  blocks_in_last_round = size_of_table %blocks_in_one_round;
    time_end = clock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    #ifdef DEBUG
      cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif
  // int start_gc,end_gc;
  // if (id==0){
  //   start_gc = 0;
  //   end_gc = size_of_table;
  // }
  // else{
  //   start_gc = size_of_table;
  //   end_gc = size_of_table*2;
  // }
  #ifdef DEBUG
    printf("Sending GC...\n");
    // printf("no of rounds = %d ;blocks in last round= %d\n",no_of_rounds,blocks_in_last_round);
  #endif

    //dummy send (for timing calculations)
    send(server_fd,buffer,1,0);
    time_beg = clock();
  for(j=0;j<no_of_rounds;++j){
    memcpy(buffer,gc.table+id*size_of_table+j*blocks_in_one_round,blocks_in_one_round*sizeof(block));
    send(server_fd,buffer,blocks_in_one_round*sizeof(block),0);
  }
  memcpy(buffer,gc.table+id*size_of_table+j*blocks_in_one_round,blocks_in_last_round*sizeof(block));
  send(server_fd,buffer,blocks_in_last_round*sizeof(block),0);
    time_end = clock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    send_bytes += size_of_table*sizeof(block);

    #ifdef DEBUG
      cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif

    //old send not optimized
  // for(j=start_gc;j<end_gc;++j){
  //   memcpy(buffer,gc.table+j,sizeof(block));
  //   send(server_fd,buffer,sizeof(block),0);
  // }

  //Sent GC-----------------------------------------------------------------------

  //Send Decommitments============================================================
  #ifdef DEBUG
    printf("Senting Decomitment info!\n");
  #endif

    //dummy send (for timing calculations)
    send(server_fd,buffer,1,0);
    time_beg = clock();
  //Garbler's index of decommitment
  memcpy(buffer,decom, sizeof(bool) * INPUT_4M);
  send(server_fd, buffer, sizeof(bool) * INPUT_4M, 0);

  //Garblers labels for decommit
  memcpy(buffer, extractedLabels, sizeof(block) * gc.n);
  send(server_fd, buffer, sizeof(block) * gc.n,0);
  //Sent Decommitments-------------------------------------------------------------
    time_end = clock();
    network_time = network_time + double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    send_bytes+=sizeof(bool) *INPUT_4M+sizeof(block) * gc.n;

    #ifdef DEBUG
      cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif

    // printf("network_time = %f\n",network_time);

    time_beg = clock();
  //receving Y from evaluator.===============================================
  block *computedOutputMap = garble_allocate_blocks(gc.m);
  bool *outputVals = (bool*) calloc(gc.m, sizeof(bool));
    time_end = clock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    #ifdef DEBUG
      cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif

    //dummy send (for timing calculations)
    recv(server_fd,buffer,1,0);
    time_beg = clock();
  recv(server_fd, buffer, sizeof(block) * gc.m, 0);
  memcpy(computedOutputMap,buffer,sizeof(block) * gc.m);
    time_end = clock();
    network_time+= double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    recv_bytes += sizeof(block) * gc.m;

    #ifdef DEBUG
      cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif


  #ifdef DEBUG
    printf("receved Y from evaluator\no/p : ");
    // for(i=0;i<10;++i){
    //   print128_num(computedOutputMap[i]);
    // }
  #endif
    time_beg = clock();
	assert(garble_map_outputs(outputMap, computedOutputMap, outputVals, gc.m) == GARBLE_OK);
  // Printing output
  // for(i=0;i<gc.m;i++){
  //   cout<<outputVals[i]<<" ";
  // }
  time_end = clock();
  comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

  #ifdef DEBUG
    cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
  #endif

  printf("\nEvaluated output successfully\n");

  /*  send(server_fd,buffer,1,0);
    time_beg = clock();
  memcpy(buffer, outputMap, sizeof(block)*2*gc.m);
  send(server_fd, buffer, sizeof(block) * 2 * gc.m,0);
    time_end = clock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
    send_bytes += sizeof(block) * 2 * gc.m;
*/

  printf("Computation time : %fms\nNetwork time : %fms\n",comp_time,network_time);
  printf("Send %f bytes\tReceived : %f bytes\n",send_bytes,recv_bytes);
  printf("Send %f KB\tReceived : %f KB\n",send_bytes/1024,recv_bytes/1024);

  close(server_fd);
}

/*######################
#### GARBLER HANDLER ###
######################*/
//thread function to handle the client garblers
int garble_handler(int id){
  u_char buffer[MAX_PAYLOAD_SIZE];
  int i,j;
  clock_t time_beg, time_end;

  //Initializing clients
  buffer[0] = EVENT_INIT_CLIENT;

  if(id == 0){
    #ifdef DEBUG
      cout<<"Handling Alice..\nsending initialization msg to Alice\n";
    #endif
    buffer[1]= 'A';
    memcpy(buffer+2, inputs+INPUT_4M/2, sizeof(bool) * INPUT_4M/4);
    //Initializing all the locks(for thread syncronization)
    commit_check_mtx.lock();
    hash_check_mtx.lock();
    eval_ready_mtx.lock();
    eval_complete.lock();
    b_check_mtx.lock();
  }
  else if(id == 1){
    #ifdef DEBUG
      cout<<"Handling Bob..\nsending initialization msg to Bob\n";
    #endif
    buffer[1]= 'B';
    memcpy(buffer+2, inputs+((3*INPUT_4M)/4), sizeof(bool) * INPUT_4M/4);
  }
  else
  {
    cout<<"Unknown paty\n";
    exit(0);
  }

    //dummy recv (for timing calculations)
    send(client_soc[id],buffer,1,0);
    time_beg = clock();
  send(client_soc[id],buffer,INPUT_4M/2+3,0);
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += INPUT_4M/2+3;

      #ifdef DEBUG
        cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
      #endif

    comp_time_mtx.unlock();
  //Sending initialization and inputs of evaluator done!!=======================

  //Receiving b values==========================================================
    //dummy send (for timing calculations)
    recv(client_soc[id],buffer,1,0);
    time_beg = clock();
  recv(client_soc[id],buffer, sizeof(bool)*INPUT_4M/2, 0);
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes += sizeof(bool)*INPUT_4M/2;

      #ifdef DEBUG
        cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
      #endif

  comp_time_mtx.unlock();

    time_beg = clock();
  if(id==0)
    memcpy(b,buffer,sizeof(bool)*INPUT_4M/2);
  else
    memcpy(b+INPUT_4M/2,buffer,sizeof(bool)*INPUT_4M/2);
  #ifdef DEBUG
    printf("Received b values\n");
  #endif
    time_end = clock();
      comp_time_mtx.lock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      comp_time_mtx.unlock();

      #ifdef DEBUG
        cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
      #endif

  //Comparing b values==========================================================
  if(id==1){
    b_check_mtx.lock();
      time_beg = clock();
    if(memcmp(b,b+INPUT_4M/2,sizeof(bool)*INPUT_4M/2)!=0){
      printf("received b values are not equal\t aborting...\n");
      for(int i=0;i<INPUT_4M;i++){
        cout<<b[i]<<" ";
      }
      exit(0);
    }
    // printf("received b values are equal\n");
    time_end = clock();
      comp_time_mtx.lock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      comp_time_mtx.unlock();

      #ifdef DEBUG
        cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
      #endif

    b_check_mtx.unlock();
  }
  else{
    b_check_mtx.unlock();
  }

  //receving commitments========================================================
  u_char commit_msg[gc.n*2][SHA256_DIGEST_LENGTH];
  int no_of_rounds = (gc.n*2/sha256_in_one_round);
  int blocks_in_last_round = gc.n*2 %blocks_in_one_round;

    //dummy send (for timing calculations)
    recv(client_soc[id],buffer,1,0);
    time_beg = clock();
  for(j=0;j< no_of_rounds;++j){
      recv(client_soc[id],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH,0);
      memcpy(&commit_msg[j*sha256_in_one_round],buffer,sha256_in_one_round*SHA256_DIGEST_LENGTH);
  }//sending last round
  recv(client_soc[id],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH,0);
  memcpy(&commit_msg[j*sha256_in_one_round],buffer,blocks_in_last_round*SHA256_DIGEST_LENGTH);
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes += gc.n*2*SHA256_DIGEST_LENGTH;

      #ifdef DEBUG
        cout<<"Total Network Time : "<< network_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
      #endif

    comp_time_mtx.unlock();

  commit_ip[id] = commit_msg;
  #ifdef DEBUG
    printf("Received All commitments from %d!\n",id);
  #endif
  //receved all commitments-----------------------------------------------------

  //varification of commitment==================================================
  if(id==1){//Bob_hanler will varify
    commit_check_mtx.lock();
      time_beg = clock();

    if(memcmp(commit_ip[0],commit_ip[1],gc.n*2*SHA256_DIGEST_LENGTH) != 0){
      cout<<"commitment for G1&G2 are not equal\naborting..\n";
      // exit(0);
    }
    // cout<<"commitment from Alice & Bob are equal\n";
    time_end = clock();
      comp_time_mtx.lock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

      #ifdef DEBUG
        cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
      #endif

      comp_time_mtx.unlock();
    commit_check_mtx.unlock();
  }
  else{
    commit_check_mtx.unlock();
  }

  //recieve hash of GC=========================================================
  u_char hash[SHA256_DIGEST_LENGTH];
  gc.output_perms = (bool *)calloc(gc.m, sizeof(bool));

    //dummy send (for timing calculations)
    recv(client_soc[id],buffer,1,0);
    time_beg = clock();
  recv(client_soc[id],buffer,SHA256_DIGEST_LENGTH,0);
  memcpy(hash,buffer,SHA256_DIGEST_LENGTH);
  gc_hash[id] = hash;

  #ifdef DEBUG
    printf("Received Hash of GC\n");
    printf("%s\n", hash);
  #endif
  if(id==1){
    recv(client_soc[id],buffer,sizeof(bool)*gc.m,0);
    recv_bytes += sizeof(bool) *gc.m;
    memcpy(gc.output_perms,buffer,sizeof(bool)*gc.m);
  }
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes += SHA256_DIGEST_LENGTH;
    comp_time_mtx.unlock();

    time_beg = clock();
  //receiving the garble circuit================================================
  int size_of_table = (gc.q - gc.nxors);
  no_of_rounds = (size_of_table/blocks_in_one_round);
  blocks_in_last_round = size_of_table %blocks_in_one_round;

    time_end = clock();
      comp_time_mtx.lock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

      #ifdef DEBUG
        cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
      #endif

      comp_time_mtx.unlock();

    //dummy send (for timing calculations)
    recv(client_soc[id],buffer,1,0);
    time_beg = clock();
  for(j=0;j<no_of_rounds;++j){
    recv(client_soc[id],buffer,blocks_in_one_round*sizeof(block),0);
    memcpy(gc.table+id*size_of_table+j*blocks_in_one_round,buffer,blocks_in_one_round*sizeof(block));
  }
  recv(client_soc[id],buffer,blocks_in_last_round*sizeof(block),0);
  memcpy(gc.table+id*size_of_table+j*blocks_in_one_round,buffer,blocks_in_last_round*sizeof(block));
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes += size_of_table * sizeof(block);
    comp_time_mtx.unlock();
  // for(j=start_gc;j<end_gc;++j){
  //   recv(client_soc[id],buffer,sizeof(block),0);
  //   memcpy(gc.table+j,buffer,sizeof(block));
  // }

  #ifdef DEBUG
    printf("Received GC!\n");
  #endif

  //checking hash of GC and received hashes=====================================
  if(id==1){
    hash_check_mtx.lock();
      time_beg = clock();//computation time
    // cout<<"Comparing hashes\n";
    u_char hash_calc[SHA256_DIGEST_LENGTH]; //calculating hash of received GC
    garble_hash(&gc, hash_calc);
    // printf("%s\n", hash_calc);

    if(memcmp(hash_calc,gc_hash[0],SHA256_DIGEST_LENGTH)!=0){
      cout<<"hash is not equal to the GC\n";
      exit(0);
    }
    else if(memcmp(gc_hash[0],gc_hash[1],SHA256_DIGEST_LENGTH)!=0){
      cout<<"hashes is not equal to each other\n";
      exit(0);
    }
    else{
      // cout<<"Hashes are equal!!!\n";
    }
    time_end = clock();
      comp_time_mtx.lock();
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

      #ifdef DEBUG
        cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
      #endif

      comp_time_mtx.unlock();
    hash_check_mtx.unlock();
  }
  else{
    hash_check_mtx.unlock();
  }

  time_beg = clock();

  //recive decomitments=========================================================
  for (int i = INPUT_4M/2; i < INPUT_4M; ++i){
      decomm[i] = (inputs[i] + b[i]) % 2;
  }
  time_end = clock();
    comp_time_mtx.lock();
    comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

    #ifdef DEBUG
      cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
    #endif

    comp_time_mtx.unlock();

    //dummy send (for timing calculations)
    recv(client_soc[id],buffer,1,0);
    time_beg = clock();
  recv(client_soc[id], buffer, sizeof(bool) * INPUT_4M, 0);
  memcpy(decomm+(id*INPUT_4M/4), buffer+(id*INPUT_4M/4), sizeof(bool) * INPUT_4M/4);
  #ifdef DEBUG
    printf("received decomitments\n");
  #endif
  //Receiving Garblers labels for decommitment====================================
  recv(client_soc[id], buffer, sizeof(block) * gc.n,0);
    time_end = clock();
    comp_time_mtx.lock();
      network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      recv_bytes += INPUT_4M + sizeof(block) * gc.n;
    comp_time_mtx.unlock();

    time_beg = clock();
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
      comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

      #ifdef DEBUG
        cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
      #endif

      comp_time_mtx.unlock();
  #ifdef DEBUG
    printf("received extractedLabels\n");
  #endif

  //Verify Decommitments===============================================
  if(id==1){
    decom_check_mtx.lock();
      time_beg = clock();
    for (i = 0; i < INPUT_4M; ++i){
       if(verify_commit((char*)&commit_msg[2*i+decomm[i]][0], extractedLabels[i], NULL, COMMIT_SCHEME_SHA256) == false){
         printf("Commitment varification(at %d) failed\n",i);
         exit(0);
       }
     }
    //  printf("Commitment varified successfully \n");
       time_end = clock();
         comp_time_mtx.lock();
         comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

         #ifdef DEBUG
           cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
         #endif

         comp_time_mtx.unlock();
    decom_check_mtx.unlock();
  }else{
    decom_check_mtx.unlock();
  }
  #ifdef DEBUG
    printf("Decomitment varification done\n");
  #endif

  //evaluating  =========================================================
  #ifdef DEBUG
    printf("Evaluation started\n");
  #endif
  if(id==1){
    eval_ready_mtx.lock();
      time_beg = clock();
    printf("Evaluation started\n");
    if(garble_eval(&gc, extractedLabels, computedOutputMap, outputVals)==GARBLE_ERR){
      printf("Evaluation failed..!\nAborting..\n");
      exit(0);
    }
      time_end = clock();
        comp_time_mtx.lock();
        comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;

        #ifdef DEBUG
          cout<<"Total Comp Time : "<< comp_time<<" Current send/recv : "<< double(time_end-time_beg)<<"\n";
        #endif

        comp_time_mtx.unlock();
    // printf("Evaluated successfully\no/p : ");
    // for(i=0;i<gc.m;i++){
    //   cout<<outputVals[i]<<" ";
    // }
    eval_ready_mtx.unlock();
    eval_complete.unlock();
  }else{
    eval_ready_mtx.unlock();
  }

  eval_complete.lock();//waiting for other handler to complete
  eval_complete.unlock();

  #ifdef DEBUG
    printf("\nSending Y(computedOutputMap) to garblers\n");
  #endif
 //block *outputMap = garble_allocate_blocks(gc.m*2);
  memcpy(buffer,computedOutputMap,gc.m*sizeof(block));
    //dummy send (for timing calculations)
    send(client_soc[id],buffer,1,0);
    time_beg = clock();
  send(client_soc[id], buffer, gc.m*sizeof(block), 0);
  if(id==0) return 0;
    time_end = clock();
    comp_time_mtx.lock();
      network_time+= double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
      send_bytes += gc.m * sizeof(block);
    comp_time_mtx.unlock();

  //Receving the decoding information
   /* recv(client_soc[id],buffer,1,0);
    time_beg = clock();
  recv(client_soc[id], buffer, gc.m*2*sizeof(block), 0);
    time_end = clock();
    network_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;*/

  if(id==1){
     /* time_beg = clock();//Computation_time
    memcpy(outputMap,buffer, gc.m*2*sizeof(block));
    assert(garble_map_outputs(outputMap, computedOutputMap, outputVals, gc.m) == GARBLE_OK);
    // for(i=0;i<gc.m;i++){
    //   cout<<outputVals[i]<<" ";
    // }
      time_end = clock();
        comp_time_mtx.lock();
        comp_time += double(time_end-time_beg)/ CLOCKS_PER_M_SEC;
        comp_time_mtx.unlock();*/
    printf("\nEvaluated output successfully\n");
    printf("Computation time : %fms\nNetwork time : %fms\n",comp_time,network_time);
    printf("Send %f bytes\tReceived : %f bytes\n",send_bytes,recv_bytes);
    printf("Send %f KB\tReceived : %f KB\n",send_bytes/1024,recv_bytes/1024);
  }
}

//P3 server open for connecting P1 & P2
void evaluator(char *ip){
    sockaddr client_addr;
    socklen_t addr_size = sizeof(client_addr);
    int server_fd;

    server_fd = socket_bind_listen(ip,SERVER_PORT);

    //Sampling inputs for evaluator
    for (size_t i = INPUT_4M/2; i < INPUT_4M; ++i) {
            inputs[i]= rand() % 2;
    }
    //allocating global variables
    gc.table = (block*) calloc(gc.q - gc.nxors,garble_table_size(&gc));
    extractedLabels = garble_allocate_blocks(gc.n);
    computedOutputMap = garble_allocate_blocks(gc.m);
    outputVals = (bool*) calloc(gc.m, sizeof(bool));
    if((client_soc[0] = accept(server_fd,(sockaddr*)(&client_addr) ,&addr_size))<0){
      cout<<"accept failed\n";
    }
    //starting Alice_handler
    thread g1 (garble_handler,0);

    if((client_soc[1] = accept(server_fd,(sockaddr*)(&client_addr) ,&addr_size))<0){
      cout<<"accept failed\n";
    }
    //Starting Bob_handler
    thread g2 (garble_handler,1);

    #ifdef DEBUG
      cout<<"\nsoc_id for g1(Alice):"<<client_soc[0]<<" ,soc_id for g2(Bob):"<<client_soc[1]<<"\n";
    #endif

    //soft decode and learn the output from
    #ifdef DEBUG
      printf("Eval main waiting for Bob_handler to exit\n");
    #endif
    close(server_fd);
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

  	return 0;

}
