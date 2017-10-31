#include "primitives.h"

typedef struct
{
	unsigned int n1, n2, m, q, r;
	garble_gate *gates;
}buildCircuit;

//TODO -with publick key
ssize_t broadcast(int sockfd1,int sockfd2, const void *buf, size_t len ,int flags){
	thread s2 (send,sockfd2,buf,len,flags);
	send(sockfd1,buf,len,flags);
	s2.join();
}

void printHex(u_char *msg_ptr , int msg_size){
	for(int i=0;i<msg_size;i++)
		cout << setw(2) << setfill('0') << (hex) << ((unsigned int) msg_ptr[i]);
	cout<<endl;
}
void print128_num(block var)
{
    uint16_t *val = (uint16_t*) &var;
    printf("Numerical: %i %i %i %i %i %i %i %i \n",
       val[0], val[1], val[2], val[3], val[4], val[5],
       val[6], val[7]);
}

void randomGen(u_char *key, int size){
	if (!RAND_bytes(key, size)) {
	    printf("Failed to create random key, isue with openSSL\n");
	}
}
void writeToFile(u_char *msg,char *file_name,int size){
	FILE *outfile;
	outfile =fopen(file_name, "wb");
	if(size==0) size = sizeof(msg);
	fwrite((char*)msg,size,1,outfile);
	fclose(outfile);
}
void readFromFile(u_char *msg,char *file_name){
	FILE *infile;
	int size;
	infile= fopen(file_name, "rb");
	fseek(infile, 0, SEEK_END);
	size = ftell(infile);
	fseek(infile, 0, SEEK_SET);
	fread((char*)msg,size,1,infile);
	fclose(infile);
}


long long current_time() {
    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // caculate milliseconds

    return milliseconds;
}

//typedef __m128i block;
void commit(commitment output, block msg, void *rand, int scheme_type){
    if(output==NULL) return;

    if(scheme_type == COMMIT_SCHEME_SHA256){
        SHA256((unsigned char *)(&msg), sizeof(block), (unsigned char *)output);
    }

}
bool verify_commit(commitment out2, block msg, void *rand, int scheme_type){
    if(out2 == NULL) return false;

    if(scheme_type == COMMIT_SCHEME_SHA256){
        unsigned char out1[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char *)(&msg), sizeof(block), (unsigned char *)out1);

        if(strncmp((const char *)out1, (const char *)out2, SHA256_DIGEST_LENGTH) == 0){
            return true;
        }
    }
    return false;
}


//typedef __m128i block;
void commitInputs(unsigned char * output, unsigned char * msg, size_t size, void *rand, int scheme_type){
    if(output==NULL) return;

    if(scheme_type == COMMIT_SCHEME_SHA256){
        SHA256(msg, size, output);
    }

}
bool verify_commitInputs(unsigned char * out2, unsigned char * msg, size_t size, void *rand, int scheme_type){
    if(out2 == NULL) return false;

    if(scheme_type == COMMIT_SCHEME_SHA256){
        unsigned char out1[SHA256_DIGEST_LENGTH];
        SHA256(msg, size, out1);

        if(strncmp((const char *)out1, (const char *)out2, SHA256_DIGEST_LENGTH) == 0){
            return true;
        }
    }
    return false;
}




bool compare_commit(char *msg1 ,char *msg2, int length){
	for(int i=0;i<length;++i){
		if(msg1[i]!=msg2[i]) return false;
	}
	return true;
}

extern "C"{
void circuitBuilding(buildCircuit *bC, garble_circuit *gc ,char* file){
	size_t i,j,k;
	int noi, noo;
	FILE *fp;
	garble_gate g;
	char str[20];

	fp = fopen(file,"r");
	if(fp==NULL)	{
		printf("File error\n");
		exit(0);
	}

	fscanf(fp,"%u %u\n", &bC->q, &bC->r);
	// printf("Gates: %u Wires: %u\n", bC->q, bC->r);

	fscanf(fp,"%u %u %u\n", &bC->n1, &bC->n2, &bC->m);
	// printf("Inputs: %u %u outputs: %u\n", bC->n1, bC->n2, bC->m);

	//bC->gates=(garble_gate*)malloc(sizeof(garble_gate) * bC->q);
	gc->gates= (garble_gate*)calloc(bC->q, sizeof(garble_gate));
	if(gc->gates==NULL)	{
		printf("Out of memory\n");
		exit(0);
	}

	i=0;gc->nxors=0;
	while(!feof(fp))
	{
		fscanf(fp,"%d %d", &noi, &noo);
		if (noi==2)
		{
			fscanf(fp,"%ld %ld %ld %s\n", &g.input0, &g.input1, &g.output, str);
		}
		else if(noi==1)
		{
			fscanf(fp,"%ld %ld %s\n", &g.input0, &g.output, str);
			g.input1 = 999;
		}

		if(strcmp(str,"AND")==0)
			g.type = GARBLE_GATE_AND;
		else if(strcmp(str,"XOR")==0){
			g.type = GARBLE_GATE_XOR;
			gc->nxors++;
		}
		else
			g.type = GARBLE_GATE_NOT;

		gc->gates[i].input0 = g.input0;
		gc->gates[i].input1 = g.input1;
		gc->gates[i].output = g.output;
		gc->gates[i].type = g.type;


		// printf("%d %d %ld %ld %ld %s\n", noi, noo, g.input0, g.input1, g.output, str);
		// printf("%ld %ld %ld %d %s\n\n", gc->gates[i].input0, gc->gates[i].input1, gc->gates[i].output, gc->gates[i].type, str);

		i++;

	}

	bC->q=i;
	fclose(fp);
}

void build(garble_circuit *gc,char* file ){
	const int times = 1,
						niterations = 1;
	garble_circuit gc1;
	buildCircuit bC;
	garble_type_e type = GARBLE_TYPE_HALFGATES;

	block seed;

	unsigned char hash[SHA_DIGEST_LENGTH];

	//build(&gc, type);
	memset(gc, '\0', sizeof(garble_circuit));
	circuitBuilding(&bC, gc, file);

	// printf("Built Circuit\n");
	garble_new(gc, bC.n1 + bC.n2, bC.m, type);
	//gc.gates = bC.gates;
	gc->r=bC.r;
	gc->q=bC.q;
	}
}
