#include "../primitives/primitives.h"
#include "../primitives/socket.h"

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

#define GC_FILE "circuits/aes.txt"
#define DEBUG

//time calculations
double comp_time = 0, network_time = 0;
double wait_time = 0;

//network bytes
double send_bytes = 0, recv_bytes = 0, broadcast_bytes = 0;

//Mutex variables for thread syncronization
mutex round_mtx[4];
mutex commit_check_mtx;
mutex decom_check_mtx;
mutex hash_check_mtx;
mutex eval_ready_mtx;
mutex eval_complete;
mutex b_check_mtx;
mutex comp_time_mtx;

//Global variables used by both threads
garble_circuit gc;
void* commit_ip[4];
void* gc_hash[4];

bool b[INPUT_4M];
bool inputs[INPUT_4M];
bool decomm[INPUT_4M];
block *extractedLabels;
block *computedOutputMap;
bool *outputVals;

//communication
// Garbler 1 v/s Garbler 2
int p0_p1_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];


  if(id == 0){//Garbler 1's side
    strcpy((char*)buffer,"hallo p1");
    cout<<"Sending to P1 :"<<buffer<<"\n";
    send(addr_soc[1],buffer,9,0);
  }

  else if(id == 1){// Garbler 2's side
    recv(addr_soc[0],buffer,9,0);
    cout<<"Recived from P0 :"<<buffer<<"\n";
  }
}

// Garbler 1 v/s Evaluator 1
int p0_p2_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];
  if(id == 0){
    strcpy((char*)buffer,"hallo");
    cout<<"Sending to P2 :"<<buffer<<"\n";
    send(addr_soc[2],buffer,6,0);
  }
  else if(id == 2){
    recv(addr_soc[0],buffer,6,0);
    cout<<"Recived from P0 :"<<buffer<<"\n";
  }
}

// Garbler 1 v/s Evaluator 2
int p0_p3_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];
  if(id == 0){
    strcpy((char*)buffer,"hallo");
    cout<<"Sending to P3 :"<<buffer<<"\n";
    send(addr_soc[3],buffer,6,0);
  }
  else if(id == 3){
    recv(addr_soc[0],buffer,6,0);
    cout<<"Recived from P0 :"<<buffer<<"\n";
  }
}

// Garbler 2 v/s Evaluator 1
int p1_p2_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];
  if(id == 1){
    strcpy((char*)buffer,"hallo");
    cout<<"Sending to P2 :"<<buffer<<"\n";
    send(addr_soc[2],buffer,6,0);
  }
  else if(id == 2){
    recv(addr_soc[1],buffer,6,0);
    cout<<"Recived from P1 :"<<buffer<<"\n";
  }
}

// Garbler 2 v/s Evaluator 2
int p1_p3_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];
  if(id == 1){
    strcpy((char*)buffer,"hallo");
    cout<<"Sending to P3 :"<<buffer;
    send(addr_soc[3],buffer,6,0);
  }
  else if(id == 3){
    recv(addr_soc[1],buffer,6,0);
    cout<<"Recived from P1 :"<<buffer;
  }
}

//  Evaluator 1 v/s Evaluator 2
int p2_p3_handler(){
  u_char buffer[MAX_PAYLOAD_SIZE];
  if(id == 2){
    strcpy((char*)buffer,"hallo");
    cout<<"Sending to P3 :"<<buffer<<"\n";
    send(addr_soc[3],buffer,6,0);
  }
  else if(id == 3){
    recv(addr_soc[2],buffer,6,0);
    cout<<"Recived from P2 :"<<buffer<<"\n";
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
    // network_time += double(time_end-time_beg)/ CLOCKS_PER_SEC;
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
    //Copying evaluator's input
    memcpy(inputs+INPUT_4M/2, buffer+2, sizeof(bool) * INPUT_4M/4);
  }
  else if(buffer[1]=='B'){
    cout<<"I\'m Bob, garbler 2(P1)\n";
    id = 1;
    //Sampling bob's input
    for (i = INPUT_4M/4; i < INPUT_4M/2; ++i){
            inputs[i]= rand() % 2;
    }
    //Copying evaluator's input
    memcpy(inputs+((3*INPUT_4M)/4), buffer+2, sizeof(bool) * INPUT_4M/4);
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
    cout<<"garblers working properly\n";
  #endif

}
l
//P2(evaluator 1) server open for connecting P0,P1 & P2
void evaluator(){
    sockaddr client_addr;
    u_char buffer[MAX_PAYLOAD_SIZE];
    socklen_t addr_size = sizeof(client_addr);
    int server_fd;

    server_fd = socket_bind_listen(ip[0],SERVER_PORT);

    //Sampling inputs for evaluator
    for (size_t i = INPUT_4M/2; i < INPUT_4M; ++i) {
            inputs[i]= rand() % 2;
    }
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
  for (size_t i = INPUT_4M/2; i < INPUT_4M; ++i) {
          inputs[i]= rand() % 2;
  }
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

    #ifdef DEBUG
      cout<<"gc file read done..\ngc->n,m,q,r,nxor "<<gc.n<<" , "<<gc.m<<" , "<<gc.q<<" , "<<gc.r<<" , "<<gc.nxors<<"\n";
    #endif

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

  	return 0;

}
