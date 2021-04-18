#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

char* iptos(u_long in);
char* ip6tos(struct sockaddr* address,char ip6str[],int sizeofip6str);
void ifprint(pcap_if_t *d);

int main(int argc, char *argv[])
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	int j=0;
	int inum;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	for(d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	printf("Select an interface(1-%i): ",i);
	scanf("%d",&inum);
	if(inum < 1 || inum > i)
	{
		printf("Selection out of range");
		return 1;
	}

	for(d=alldevs,j=0;j<inum-1;d=d->next,j++);

	ifprint(d);
	return(0);
}

void ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
  char ip6str[128];

  /* Name */
  printf("\n%s\n",d->name);

  /* Description */
  if (d->description)
    printf("\tDescription: %s\n",d->description);

  /* Loopback Address*/
  printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

  /* IP addresses */
  for(a=d->addresses;a;a=a->next) {
    printf("\tAddress Family: #%d\n",a->addr->sa_family);
  
    switch(a->addr->sa_family)
    {
      case AF_INET:
        printf("\tAddress Family Name: AF_INET\n");
        if (a->addr)
          printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        if (a->netmask)
          printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
        if (a->broadaddr)
          printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
        if (a->dstaddr)
          printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
        break;

	  case AF_INET6:
        printf("\tAddress Family Name: AF_INET6\n");
        if (a->addr)
          printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
        break;

	  default:
        printf("\tAddress Family Name: Unknown\n");
        break;
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