#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "netCanvas.h"



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

  /* Navigate to selected device */
	for(d=alldevs,j=0;j<inum-1;d=d->next,j++);

  
	interface_print(d);
  pcap_freealldevs(alldevs);

	return(0);
}