#include <time.h>
#include "netcanvas.h"

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm ltime;
    time_t local_tv_sec;
    char timestr[16];
    
    local_tv_sec = header->ts.tv_sec;
    localtime_r(&local_tv_sec,&ltime);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

    printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);
}