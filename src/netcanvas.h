#pragma once
/*
*
*
*
*/
#include <pcap.h>

/* Packet data structs */

/* 4 bytes IP Address */
typedef struct ip_address{
    u_char b1;
    u_char b2;
    u_char b3;
    u_char b4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char ver_ihl;             /* Version (4 bits) + Internet header length (4 bits) */
    u_char tos;                 /* Type of service */
    u_short tlen;               /* Total length */
    u_short identificataion;    /* Identification */
    u_short flags_fo;           /* Flags (3 bits) + Fragment offset (13 bits) */
    u_char ttl;                 /* Time to live */
    u_char proto;               /* Protocol */
    u_short crc;                /* Header checksum */
    ip_address s_addr;          /* Source address */
    ip_address d_addr;          /* Destination address */
    u_int op_pad;               /* Option + Padding */
}ip_header;

/* UDP header */
typedef struct udp_header{
    u_short sport;              /* Source port */
    u_short dport;              /* Destination port */
    u_short len;                /* Datagram length */
    u_short crc;                /* Checksum */
}upd_header;

/* Address function prototypes */
char* iptos(u_long in);
char* ip6tos(struct sockaddr* address,char ip6str[],int sizeofip6str);

/* Interface function prototypes */
void interface_print(pcap_if_t *);

/* Packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);