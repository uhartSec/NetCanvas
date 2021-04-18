#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
char* iptos(u_long in);
char* ip6tos(struct sockaddr* address,char ip6str[],int sizeofip6str);
void ifprint(pcap_if_t *d);

/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

int main(int argc, char *argv[])
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_addr *a;
	int i=0;
	int j=0;
	char choice;
	int inum;
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for(d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure pcap is installed.\n");
		return -1;
	}


	/* Print all the available information on the given interface */
	printf("Select an interface(1-%i): ",i);
	scanf("%d",&inum);
	if(inum < 1 || inum > i)
	{
		printf("Selection out of range\n");
		return 1;
	}

	for(d=alldevs,j=1;j<inum;d=d->next,j++);

	ifprint(d);
	printf("Start capture? y/n: ");
	scanf(" %c",&choice);
	if(choice == 'y' || choice == 'Y')
	{
		if ( (adhandle = pcap_open_live(d->name,			// name of the device
				  65536,									// portion of the packet to capture
															// 65536 guarantees that the whole packet will be captured on all the link layers
				  PCAP_OPENFLAG_PROMISCUOUS, 				// promiscuous mode
				  1000,										// read timeout
				  errbuf									// error buffer
				  ) ) == NULL)
		{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by pcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
		}
	}
	else{
		return(0);
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	a = d->addresses;
	if(d->addresses != NULL)
	{
		while(a->netmask == NULL && a!=NULL)
		{
			a = a->next;
		}
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(a->netmask))->sin_addr.s_addr;
	}
	else
	{
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff;
	}

	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->name);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	// struct tm ltime;
	struct tm ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport,dport;
	time_t local_tv_sec;

	/*
	 * unused variables
	 */
	(void)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_r(&local_tv_sec, &ltime);
	strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
	printf("%s.%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);

	/* retireve the position of the ip header */
	ih = (ip_header *) (pkt_data +
		14); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *) ((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs( uh->sport );
	dport = ntohs( uh->dport );

	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
}

void ifprint(pcap_if_t *d)
{
  struct pcap_addr *a;
  char ip6str[128];

  /* Name */

  printf("%s\n",d->name);

  /* Description */
  if (d->description)
    printf("\tDescription: %s\n",d->description);

  /* Loopback Address*/
  printf("\tLoopback: %s\n\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

  /* IP addresses */
  for(a=d->addresses;a!=NULL;a=a->next) {
    printf("\tAddress Family: #%d\n",a->addr->sa_family);
    if(a->addr->sa_family== AF_INET)
    {
    	printf("\tAddress Family Name: AF_INET\n");
        if (a->addr)
          printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        if (a->netmask)
          printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
        if (a->broadaddr)
          printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
        if (a->dstaddr)
          printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
      	printf("\n");
    }
    else if(a->addr->sa_family==AF_INET6)
    {
    	printf("\tAddress Family Name: AF_INET6\n");
        if (a->addr)
          printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
      	printf("\n");
    }
    else if(a->addr->sa_family==AF_PACKET)
    {
    	printf("\tAddress Family Name: AF_PACKET\n\n");
    }
    else
    {
    	printf("\tAddress Family Name: Unknown\n\n");
    }
  }
  printf("\n");
}


char* iptos(u_long input)
{
	// 12 buffers, each big enough to hold maximum-sized IP address
    //   and nul terminator.
    static char output[12][3*4+3+1];

    // Last buffer used.
    static short which;

    // Get uns. char pointer to IP address.
    u_char *p;
    p = (u_char *)&input;

    // Move to next string buffer, wrapping if necessary.
    which = (which + 1 == 12 ? 0 : which + 1);

    // Output IP address by accessing individual unsigned chars in it.
    snprintf(output[which], sizeof(output[which]),
        "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

    // Return the current buffer.
    return output[which];
}

char* ip6tos(struct sockaddr* sa,char s[],int maxlen)
{
	inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, maxlen);
	return s;
}