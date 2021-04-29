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

/* Packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);