#pragma once
/*
*
*
*
*/
#include <pcap.h>


/* Address function prototypes */
char* iptos(u_long in);
char* ip6tos(struct sockaddr* address,char ip6str[],int sizeofip6str);

/* Interface function prototypes */
void interface_print(pcap_if_t *);