#include "../primitives/primitives.h"
//
// #include "../JustGarble/include/gates.h"
// #include "../JustGarble/include/circuits.h"
// // #include "../JustGarble/include/justGarble.h"
// // #include "../JustGarble/include/common.h"
// // #include "../JustGarble/include/util.h"
//
// #define DEBUG
// #define SHARED_SEED 24
// /*
//  Generate circuits for AES-128. Where assuming there are
//  three parties: A, B and C. A and B each provide 128bit  XOR share of
//  the secret key. I.e., the secret key to AES is the XOR of A and B's
//  input. C provides 128bit of message to encrypt.
//
//  Steps:
//  (1) Input length = 128 (message) + 128*2 (shares of the secret key)
//  (2) The shares are XOR first to recovery AES secret key. Then, using
//  AES' 128bit Key Expanding algorithm to generate round keys.
//  (3) Set addKeyInput = [message || round keys]
//  (4) Using JustGarble's existing code to performance AES encryption.
//
//  */
// void build_circuite_from_file(){
//    int n_gates,n_wires,n_input1,n_input2,n_output;
//    int input0,input1,output;
//    string line;
//    fstream file;
//
//    file.open("circuits/aes128_non_expanded.txt",ios::in);
//    if (!file.is_open()){
//      cout<<"File not found Exiting";
//    }
//    //TODO
//    //reading circuit information from file(hard coded need to change)
//    getline(file,line,' ');//space delimiter
//    n_gates = stoi(line);
//    getline(file,line);
//    n_wires = stoi(line);
//
//    getline(file,line,' ');
//    n_input1 = stoi(line);
//    getline(file,line,' ');
//    n_input2 = stoi(line);
//    getline(file,line,' ');
//    getline(file,line,' ');
//    getline(file,line);
//    n_output = stoi(line);
//
//      #ifdef DEBUG
//        cout<<"Parameters of Circuits read from file: gates-"<<n_gates<<"; wires-"<<n_wires<<"; input1-"<<n_input1<<" ;input2-"<<n_input2<<" ;output-"<<n_output<<"\n";
//      #endif
//
//    //initialize garble circuit
//    GarbledCircuit garbledCircuit;
//    GarblingContext garblingContext;
//    block inputLabels[2 * (n_input1+n_input2)];
//    block outputMap[2* n_output];
//    int output_array[n_output];
//    createInputLabels(inputLabels, n_input1+n_input2);
//    createEmptyGarbledCircuit(&garbledCircuit,n_input1+n_input2,n_output,n_gates,n_wires,inputLabels);
//    startBuilding(&garbledCircuit, &garblingContext);
//
//      #ifdef DEBUG
//        cout<<"Garbled circuit initialization completerd\nStart building...\n";
//      #endif
//
//    getline(file,line);//
//    while(getline(file,line)){
//      char gate_line[30];
//      vector<string> substring;
//      strcpy(gate_line,line.c_str());
//
//      //substring array filled with information of one gate
//      int pos=0,i=1;
//      while(gate_line[i-1] != '\0'){
//        if(gate_line[i]==' ' || gate_line[i]=='\0'){
//          substring.push_back(line.substr(pos,i-pos));
//          pos = i+1;
//        }
//        i++;
//      }
//
//      //Building gates
//      if(stoi(substring[0])==1){//INV gate
//        input0 = stoi(substring[2]);
//        output = stoi(substring[3]);
//        NOTGate(&garbledCircuit, &garblingContext, input0, output);
//      }
//      else if(stoi(substring[0])==2){//2 input 1 output gates
//        input0 = stoi(substring[2]);
//        input1 = stoi(substring[3]);
//        output = stoi(substring[4]);
//        if(substring[5].compare("XOR")){
//          XORGate(&garbledCircuit, &garblingContext, input0,input1, output);
//        }
//        else if(substring[5].compare("AND")){
//          ANDGate(&garbledCircuit, &garblingContext, input0,input1, output);
//        }
//        else{
//          cout<<"Unknown gate.. Exiting\n";
//          exit(0);
//        }
//      }
//      else{
//        cout<<"Unknown gate.. Exiting\n";
//        exit(0);
//      }
//    }
//    finishBuilding(&garbledCircuit, &garblingContext,outputMap,output_array);
//
//      #ifdef DEBUG
//        cout<<"Garbled circuit finished building\nWriting to a file...\n";
//      #endif
//
//    char filename[]="test.jgc";
//    writeCircuitToFile(&garbledCircuit,filename);
//  }
//
// void test(){
//   GarbledCircuit garbledCircuit;
//   GarblingContext garblingContext;
//   int output_array[garbledCircuit.m];
//
//   build_circuite_from_file();
//   readCircuitFromFile(&garbledCircuit,"test.jgc");
//
//     #ifdef DEBUG
//       cout<<"Garbled circuit read from the file....done!\n";
//     #endif
//
//   block inputLabels[2 * garbledCircuit.n];
//   block outputMap[2* garbledCircuit.m];
//
//   garbledCircuit.seed = SHARED_SEED;
//   createInputLabels(inputLabels, garbledCircuit.n);
//   garbleCircuit(&garbledCircuit,inputLabels,outputMap);
//
//     #ifdef DEBUG
//       cout<<"Garbling completed with seed:"<<garbledCircuit.seed<<"\nExtracting output...\n";
//     #endif
//
//   block extractedLabels[garbledCircuit.n];
//   block extractedoutputMap[garbledCircuit.m];
//   int inputbits[garbledCircuit.n];
//   for(int i=0;i<garbledCircuit.n;++i) inputbits[i]=1;
//   int outputbits[garbledCircuit.m];
//   extractLabels(extractedLabels,inputLabels,inputbits,garbledCircuit.n);
//   evaluate(&garbledCircuit,extractedLabels,extractedoutputMap);
//   mapOutputs(outputMap,extractedoutputMap,outputbits,garbledCircuit.m);
//
//     #ifdef DEBUG
//       cout<<"Got output.. printing..\n";
//     #endif
//
//   for(int i=0;i<garbledCircuit.m;++i){
//     cout<<outputbits[i]<<" ";
//   }
// }
//
// //Copied from MRZ implemetation
// int GF256xtime(GarbledCircuit *gc, GarblingContext *garblingContext, int *input, int *output){
//     int t = input[0];
//     //m(x) = x^8 + x^4 +x^3 + x +1
//
//     output[4] = getNextWire(garblingContext);
//     output[3] = getNextWire(garblingContext);
//     output[1] = getNextWire(garblingContext);
//     // (0, 0, 0, 1, 1, 0, 1, 1)
//     output[7] = input[6];
//     output[6] = input[5];
//     output[5] = input[4];
//     XORGate(gc, garblingContext, t, input[3], output[4]);
//     XORGate(gc, garblingContext, t, input[2], output[3]);
//     output[2] = input[1];
//     XORGate(gc, garblingContext, t, input[0], output[1]);
//     output[0] = t;
//
// }
//
// int RconXORCircuit(GarbledCircuit *gc, GarblingContext *garblingContext, int index, int *input, int *output){
//     static int u[8];
//     int v[8];
//     if(index == 1){
//         //initially, set u = [1] in GF(2^8)
//         for(int i=0; i<7; i++){
//             u[i] = fixedZeroWire(gc, garblingContext);
//         }
//         u[7] = fixedOneWire(gc, garblingContext);
//     }
//     GF256xtime(gc, garblingContext, u, v);
//     for(int i = 0; i<8; i++){
//         output[i] = getNextWire(garblingContext);
//         XORGate(gc, garblingContext, input[i], v[i], output[i]);
//     }
//     for(int i=0; i<8; i++){
//         u[i] = v[i];
//     }
//     return 0;
// }
//
// int AES128_Key_Expand_Circuit(GarbledCircuit *gc, GarblingContext *garblingContext, int * round_keys){
//     int round = 10;
//     int Nb = 4;
//     int Nk = 4;
//     int w[4][8]; // 1 word = 32bits
//     int v[4][8];
//     int temp[8];
//     int a, b, j;
//     int rcon_i=1;
//     int internalWire;
//
//     //Initially, round_key[0..127] keeps the secret key and is expanded.
//     for(int i = Nk; i < Nb*(round+1); i++){
//         for(a = 0; a < 4; a++){
//             for(b = 0; b < 8; b++){
//                 w[a][b] = round_keys[(i-1)*32+8*a+b];
//             }
//         }
//
//         if(i % Nk == 0){
//             //rotate [w0, w1, w2, w3] --> [w1, w2, w3, w0]
//             for(b = 0; b < 8; b++){
//                 temp[b] = w[0][b];
//                 w[0][b] = w[1][b];
//                 w[1][b] = w[2][b];
//                 w[2][b] = w[3][b];
//                 w[3][b] = temp[b];
//             }
//
//             for(a = 0; a < 4; a++){
//                 //subWord (SBox)
//                 NewSBOXCircuit(gc, garblingContext, w[a], temp);
//                 // XOR Rcon[i/Nk]
//                 if(a == 0){
//                     RconXORCircuit(gc, garblingContext,  i/Nk, temp, w[a]);
//                 }else{
//                     for(b=0; b<8; b++){
//                         w[a][b] = temp[b];
//                     }
//                 }
//
//             }
//
//         }
//
//         for(a =0; a<4; a++){
//             for(b=0; b<8; b++){
//                 round_keys[i*32+8*a+b] = getNextWire(garblingContext);
//                 XORGate(gc, garblingContext, w[a][b], round_keys[(i-Nk)*32+8*a+b], round_keys[i*32+8*a+b]); // w[i] = w[i-Nk] xor temp
//             }
//         }
//
//     }
//     return 0;
//
// }
//
// void buildAESCircuit() {
// 	srand(time(NULL));
// 	GarbledCircuit garbledCircuit;
// 	GarblingContext garblingContext;
//
// 	int roundLimit = 10;
//     int aes128_block_size = 128;
//     int input_size = 128 + 128 + 128; //Num of input bit
// 	int round_keys_message_size = 128 * (roundLimit + 1)+128; //Num of bits for round keys + message
// 	int m = 128; // Num of output bits
// 	int q = 50000; //Just an upper bound
// 	int r = 50000;
// 	//int inp[input_size];
// 	//countToN(inp, input_size);
// 	int addKeyInputs[round_keys_message_size];
// 	int addKeyOutputs[aes128_block_size];
// 	int subBytesOutputs[aes128_block_size];
// 	int shiftRowsOutputs[aes128_block_size];
// 	int mixColumnOutputs[aes128_block_size];
// 	int round;
// 	block labels[2 * input_size];
// 	block outputbs[m];
// 	OutputMap outputMap = outputbs;
// 	InputLabels inputLabels = labels;
// 	int i;
//
// 	createInputLabels(inputLabels, input_size);
// 	createEmptyGarbledCircuit(&garbledCircuit, input_size, m, q, r, inputLabels);
// 	startBuilding(&garbledCircuit, &garblingContext);
//
//     //The ids fo inputs:
//     //message (C's input): 0--127
//     // Share 1 of the secret key (A's input): 128--255
//     //Share 2 of the secret key (B's input): 256--383
//
// 	countToN(addKeyInputs, input_size);
//
//     //Step2: XOR two shares
//     int temp[aes128_block_size];
//     XORCircuit(&garbledCircuit, &garblingContext, 256, addKeyInputs+128, temp);
//     for(int i=0; i<128; i++){
//         addKeyInputs[128+i] = temp[i];
//     }
//
//     //Step 3: Expanding round keys.
//     AES128_Key_Expand_Circuit(&garbledCircuit, &garblingContext, addKeyInputs+128);
//     /*Now addKeyInputs= [0--127 (message) || expanded keys]
//      which fits JustGarble's AES-128 encryption procedure.
//      */
//
// 	for (round = 0; round < roundLimit; round++) {
//
// 		AddRoundKey(&garbledCircuit, &garblingContext, addKeyInputs,
//                     addKeyOutputs);
//
// 		for (i = 0; i < 16; i++) {
// 			SubBytes(&garbledCircuit, &garblingContext, addKeyOutputs + 8 * i,
//                      subBytesOutputs + 8 * i);
// 		}
//
// 		ShiftRows(&garbledCircuit, &garblingContext, subBytesOutputs,
//                   shiftRowsOutputs);
//
//         if(round == roundLimit -1){ //Last round is no MixColumns.
//             for(i =0; i< 128; i++){
//                 mixColumnOutputs[i] = shiftRowsOutputs[i];
//             }
//         }else{
//             for (i = 0; i < 4; i++) {
//                 MixColumns(&garbledCircuit, &garblingContext,
//                            shiftRowsOutputs + i * 32, mixColumnOutputs + 32 * i);
//             }
//         }
// 		for (i = 0; i < 128; i++) {
// 			addKeyInputs[i] = mixColumnOutputs[i];
// 			addKeyInputs[i + 128] = addKeyInputs[(round + 2) * 128 + i];
// 		}
// 	}
//
// 	finishBuilding(&garbledCircuit, &garblingContext, outputMap, addKeyInputs);
// 	writeCircuitToFile(&garbledCircuit, AES128_3PC_CIRCUIT_FILE);
// }
//
// void print128_numxx(block *var){
//     short int *val = (short int*) var;
//     printf("Numerical: %i %i %i %i %i %i %i %i \n",
//            val[0], val[1], val[2], val[3], val[4], val[5],
//            val[6], val[7]);
// }
int main(){}
//   // test();
//   // buildAESCircuit();
//   build_circuite_from_file();
//   GarbledCircuit garbledCircuit;
//   GarblingContext garblingContext;
//   int output_array[garbledCircuit.m];
//
//   // build_circuite_from_file();
//   readCircuitFromFile(&garbledCircuit,"test.jgc");
//   // readCircuitFromFile(&garbledCircuit,AES128_3PC_CIRCUIT_FILE);
//
//     #ifdef DEBUG
//       cout<<"Garbled circuit read from the file....done!\n";
//     #endif
//
//   block inputLabels[2 * garbledCircuit.n];
//   block outputMap[2* garbledCircuit.m];
//
//   garbledCircuit.seed = SHARED_SEED;
//   // createInputLabels(inputLabels, garbledCircuit.n);
//   //
//   //   #ifdef DEBUG
//   //     cout<<"Input Labels\n";
//   //     for(int i=0;i< garbledCircuit.n*2;i++){
//   //       print128_num(inputLabels[i]);
//   //     }
//   //   #endif
//
//   garbleCircuit(&garbledCircuit,inputLabels,outputMap);
//
//     #ifdef DEBUG
//       cout<<"Input Labels\n";
//       for(int i=0;i< garbledCircuit.n*2;i++){
//         print128_num(inputLabels[i]);
//       }
//     #endif
//
//     #ifdef DEBUG
//       cout<<"Output map\n";
//       for(int i=0;i< garbledCircuit.m*2;i++){
//         print128_num(outputMap[i]);
//       }
//     #endif
//
//     #ifdef DEBUG
//       cout<<"Garbling completed with seed:"<<garbledCircuit.seed<<"\nExtracting output...\n";
//     #endif
//
//   block extractedLabels[garbledCircuit.n];
//   block extractedoutputMap[garbledCircuit.m];
//   int inputbits[garbledCircuit.n];
//   for(int i=0;i<garbledCircuit.n;++i){
//     inputbits[i]=0;
//     if(i%2==1) inputbits[i]=1;
//   }
//   int outputbits[garbledCircuit.m];
//   extractLabels(extractedLabels,inputLabels,inputbits,garbledCircuit.n);
//
//     #ifdef DEBUG
//       cout<<"Extracted input Labels\n";
//       for(int i=0;i< garbledCircuit.n;i++){
//         print128_num(extractedLabels[i]);
//       }
//       print128_num(xorBlocks(xorBlocks(extractedLabels[0],extractedLabels[1]),xorBlocks(extractedLabels[2],extractedLabels[3])));
//     #endif
//
//   evaluate(&garbledCircuit,extractedLabels,extractedoutputMap);
//
//       #ifdef DEBUG
//         cout<<"Extracted Output map after evaluate\n";
//         for(int i=0;i< garbledCircuit.m;i++){
//           print128_num(extractedoutputMap[i]);
//         }
//       #endif
//
//   mapOutputs(outputMap,extractedoutputMap,outputbits,garbledCircuit.m);
//
//     #ifdef DEBUG
//       cout<<"Got output.. printing..\n";
//     #endif
//
//     #ifdef DEBUG
//       cout<<"Input bits\n";
//       for(int i=0;i<garbledCircuit.n;++i){
//         cout<<inputbits[i]<<" ";
//       }
//       cout<<"\nOutput bits\n";
//       for(int i=0;i<garbledCircuit.m;++i){
//         cout<<outputbits[i]<<" ";
//       }
//     #endif
// }
