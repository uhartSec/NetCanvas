#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int main(int argc, char **argv){

    char *dev; //name of the device
    char *net; //dot notation of the network address
    char *mask; // dot notation of the network mask
    int return_code; //return code

    //error capture buffer
    char errbuf[PCAP_ERRBUF_SIZE];
     
    

     
    
}
