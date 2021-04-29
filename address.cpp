/*
*
*
*
*/

#include "netCanvas.h"
#include <stdlib.h>

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