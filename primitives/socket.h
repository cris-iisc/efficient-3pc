
#ifndef SOCKET_H
#define SOCKET_H

#include "primitives.h"

//40KB
#define MAXSOCKETSIZE 40960

#define MAX_PAYLOAD_SIZE (MAXSOCKETSIZE-512)


//Define for Client Socket Events
#define EVENT_COIN  55
#define EVENT_SEND_GARBLED_CIRCUITS 56
#define EVENT_SEND_COMMIT   57
#define EVENT_INIT_CLIENT   58
#define EVENT_SEND_LABEL    59
#define EVENT_EVAL_READY    60
#define EVENT_SEND_GLOBAL_KEY   61


//Define for Server Socket Events
#define EVENT_ACK_GARBLED_CIRCUITS  114
#define EVENT_ACK_COMMIT    113
#define EVENT_ACK_INIT_CLIENT   112
#define EVENT_ACK_LABEL        111
#define EVENT_ACK_GLOBAL_KEY    110


int socket_connect(const char* addr, int port);
int socket_bind_listen(const char* addr, int port);

struct client_info{
    int client_socket_fds;
};

struct Socket_Msg{
    char event_type;
};

struct Init_Client_Msg{
    char event_type;
    char client_name;
};

struct GlobalKey_Msg{
    char event_type;
    block globalKey;
};

struct Send_Circuit_Msg{
    char event_type;
    int num_gates; //num of tables (gates).

    int start_index;
    int end_index;

    size_t buf_size;
    char buf[MAX_PAYLOAD_SIZE];
};


struct Commit_Msg{
    char event_type;
    int index;
    int num_commit;
    size_t buf_size;
    char buf[MAX_PAYLOAD_SIZE];

};

struct Label_Msg{
    char event_type;
    int num_label;
    size_t buf_size;
    char buf[MAX_PAYLOAD_SIZE]; //MsgPacked
    //block label;
    //block label1; //label1 is valid only when sending C's input labels.
};

struct Ack_Init_Msg{
    char event_type;
    char clientID;
};

struct Ack_Circuit_Msg{
    char event_type;
    int index;
};


#endif /* defined(SOCKET_H) */
