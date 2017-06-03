/*==========================================
ICMP myPING program using RAW sockets
Author: Spencer Kitchen
CS 455 Introduction to Computer Networks
Due: December 5
Programming Assignment (Optional)
==========================================*/

/*** Necessary Header files for ICMP & RAW socket. 
NOTE: This is a BSD RAW socket implementation. 
      Will only run on BSD & macOSX ***/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>     // for RAW socket
#include <sys/time.h>       // to calculate RTT
// Need for ip & icmp prebuilt header structures
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>          // errno, perror()

char dst_addr[100]; // holds destination ip address
char src_addr[100]; // holds source ip address
char *dst_ip;      // Holds resolved DNS from dst_addr

/*==========================================
FUNCTION DECLORATIONS
==========================================*/ 
unsigned short in_cksum(unsigned short *, int);
void parse_argvs(char**, char*, char* );
void usage();
char* getip();
long int min(long int x, long int y);
long int max(long int x, long int y);
char *allocate_strmem (int);
void printTitle();

/*==========================================
MAIN
==========================================*/ 
int main(int argc, char* argv[]) {
    struct ip ip;
    struct ip ip_reply;
    struct icmp icmp;
    struct sockaddr_in connection, *ipv4;
    char* packet;   // packet to send
    char* buffer;   // holds response 
    int sockfd;
    int optval;
    unsigned int addrlen;
    struct addrinfo hints, *res;
    int status;
    void *tmp;
     
    if (getuid() != 0) {
        fprintf(stderr, "%s: root privelidges needed\n", *(argv + 0));
        exit(EXIT_FAILURE);
    }
    
    // get source and destination addresses
    parse_argvs(argv, dst_addr, src_addr);
    printTitle();
    printf("\nSOURCE ADDRESS: %s\t\t", src_addr);
    printf("DESTINATION ADDRESS: %s\n", dst_addr);
    printf("--------------------------------------------------------------------------------\n\n");

    /*==========================================
    Resolve DNS of destination address
    ==========================================*/
    // make room for ipv4 address
    dst_ip = allocate_strmem (INET_ADDRSTRLEN); 
    // Fill out hints for getaddrinfo().
    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    // Resolve target using getaddrinfo().
    if ((status = getaddrinfo (dst_addr, NULL, &hints, &res)) != 0) {
        fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
        exit (EXIT_FAILURE);
    }
    ipv4 = (struct sockaddr_in *) res->ai_addr;
    tmp = &(ipv4->sin_addr);
    if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
        status = errno;
        fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }
    freeaddrinfo (res);
    printf("RESOLVED DOMAIN NAME: %s ---> %s\n\n", dst_addr, dst_ip );
     
    /*==========================================
    Make space for our packet & buffer
    ==========================================*/
    packet = malloc(sizeof(struct ip) + sizeof(struct icmp));
    buffer = malloc(sizeof(struct ip) + sizeof(struct icmp));
     
    /*==========================================
    Fill Layer II (IP protocol) fields. 
    ==========================================*/ 
    /**** Header length (including options) in units of 32 bits (4 bytes). 
    Not sending any IP options so IP header length is 20 bytes. ******/
    ip.ip_hl = 0x5;                                     // (20 / 4 = 5)
    ip.ip_v = 0x4;                                      // IPV4 -> 4
    ip.ip_tos = 0x0;                                    // Type of Service. Packet precedence
    ip.ip_len = sizeof(struct ip) + sizeof(struct icmp);// Length of packet
    ip.ip_id = random();                                // random id, uniquely identifies packet
    ip.ip_off = 0x0;                                    // No offset, beginning of packet
    ip.ip_ttl = 255;                                    // time out
    ip.ip_p = IPPROTO_ICMP;                             // Using ICMP protocall (Layer III)
    ip.ip_src.s_addr = inet_addr(src_addr);             // Source address
    ip.ip_dst.s_addr = inet_addr(dst_ip);               // Destination address
    
    // finished with IP header. Copy it into the begining of our packet
    memcpy(packet, &ip, sizeof(ip));
     
    /*==========================================
    Create our raw socket with ICMP protocall
    ==========================================*/ 
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
        perror("socket");
        exit(EXIT_FAILURE);
    }
     
    //Tell kernel that we've prepared the IP header. Dont want kernel to make headers
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));
     
    /*==========================================
    Fill Layer III (ICMP protocol) fields.
    ==========================================*/
    icmp.icmp_type = ICMP_ECHO;     // We want response back from destination
    icmp.icmp_code = 0;             // Code 0. Echo Request.
    icmp.icmp_id = 0;               // ID of header
    icmp.icmp_seq = 0;              // must be 0
    icmp.icmp_cksum = 0;            // must be 0 before passing into cksum()

    /*** Pass the ICMP packet into the cksum function. Store the returned 
     value in the checksum field of ICMP header ***/
    icmp.icmp_cksum =  in_cksum((unsigned short *)&icmp, sizeof(struct icmp));

    /*** Pass the IP header and its length into the cksum function. 
    The function returns us as 16-bit checksum value for the header ***/
    ip.ip_sum = in_cksum((unsigned short *)&ip, sizeof(struct ip));

    // Add the ICMP header to the packet after IP header
    memcpy(packet + sizeof(struct ip), &icmp, sizeof(struct icmp));

    /*==========================================
    Fill Layer I (family, destination) fields.
    ==========================================*/
    /***  Fill in a struct in_addr with the desired destination IP 
    address, and pass this structure to the sendto(2) system call ***/
    connection.sin_family = AF_INET;
    connection.sin_addr.s_addr = ip.ip_dst.s_addr;
     
    // Holds the RTT time for 3 different pings
    long int ping1, ping2, ping3;
    int sent = 1; // Start at first ping request

    // Send 3 packets
    while (sent < 4) {
        struct timeval tvalBefore, tvalAfter; 
        // Get the system time BEFORE sending packet
        gettimeofday (&tvalBefore, NULL);   

        /*** Tell where to send the raw IP datagram. sendto(2) and 
        sendmsg(2) system calls are designed to handle this ***/
        sendto(sockfd, packet, ip.ip_len, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));
        printf(" > SENT %lu byte packet to %s\t", sizeof(packet), dst_ip);
     
        // Wait for response from destination
        addrlen = sizeof(connection);
        if (recvfrom(sockfd, buffer, sizeof(struct ip) + sizeof(struct icmp), 0, (struct sockaddr *)&connection, &addrlen) == -1) {
            perror("recv");
        }
        else {
            // Get the system time AFTER sending packet
            gettimeofday (&tvalAfter, NULL);
            printf(" > RECIEVED %lu byte reply from %s\n", sizeof(buffer), dst_ip);
            printf("   RTT time in microseconds: %ld microseconds\n\n",
            ((tvalAfter.tv_sec - tvalBefore.tv_sec)*1000000L+tvalAfter.tv_usec) - tvalBefore.tv_usec);
        }
        //  save packet time output for min/max/avg calcualtions
        if (sent == 1) ping1 = ((tvalAfter.tv_sec - tvalBefore.tv_sec)*1000000L+tvalAfter.tv_usec) - tvalBefore.tv_usec;
        else if (sent == 2) ping2 = ((tvalAfter.tv_sec - tvalBefore.tv_sec)*1000000L+tvalAfter.tv_usec) - tvalBefore.tv_usec;
        else if (sent == 3) ping3 = ((tvalAfter.tv_sec - tvalBefore.tv_sec)*1000000L+tvalAfter.tv_usec) - tvalBefore.tv_usec;
        sent++;
        fflush(stdout);
    }
    /*==========================================
    Print out packet RTT times
    ==========================================*/
    printf("PACKET RTT TIMES:\n");
    printf("-----------------\n");
    printf ("packet #1 RTT: %ld microseconds\n", ping1);
    printf ("packet #2 RTT: %ld microseconds\n", ping2);
    printf ("packet #3 RTT: %ld microseconds\n\n", ping3);

    /*==========================================
    Calulate min/max/average
    ==========================================*/
    long int Min , Max, Average;
    Min = min(min(ping1, ping2), ping3);
    Max = max(max(ping1, ping2), ping3);
    Average = (ping1 + ping2 + ping3)/3;

    printf("MIN/MAX/AVERAGE(AVG) RTT TIMES:\n");
    printf("-------------------------------\n");
    printf("Min Ping: %lu microseconds\n", Min );
    printf("Max Ping: %lu microseconds\n", Max );
    printf("Avg Ping: %lu microseconds\n\n", Average );

    close(sockfd);
    return 0;
}
 
/*==========================================
FUNCTIONS
==========================================*/ 
// For getting source and destination ip addresses
void parse_argvs(char** argv, char* dst, char* src) {
    int i;
    if(!(*(argv + 1))) {
        /* there are no options on the command line */
        usage();
        exit(EXIT_FAILURE); 
    }
    if (*(argv + 1) && (!(*(argv + 2)))) {
        /*** only one argument provided assume it is the 
        destination server. source address is local host ***/
        strncpy(dst, *(argv + 1), 100);
        strncpy(src, getip(), 100);
        return;
    }
    else if ((*(argv + 1) && (*(argv + 2)))){
        /*** both the destination and source address are defined for now 
        only implemented is a source address and destination address ***/
        strncpy(dst, *(argv + 1), 100);
        i = 2;
        while(*(argv + i + 1)) {
            if (strncmp(*(argv + i), "-s", 2) == 0) {
                strncpy(src, *(argv + i + 1), 100);
                break;
            }
            i++;
        }
    }
}
 
// For error output 
void usage() {
    fprintf(stderr, "\nUsage: myPING [destination] <-s [source]>\n");
    fprintf(stderr, "Destination must be provided\n");
    fprintf(stderr, "Source is optional\n");
    fprintf(stderr, "To add source, add -s flag\n\n");
}
 
// get local ip address  
char* getip() {
    char buffer[256];
    struct hostent* h;
    gethostname(buffer, 256);
    h = gethostbyname(buffer);
    return inet_ntoa(*(struct in_addr *)h->h_addr);
}

/***** Internet checksum function (from BSD Tahoe) We can use this function to 
calculate checksums for all layers. ICMP protocol mandates checksum, so we 
have to calculate it. *********/
unsigned short in_cksum(unsigned short *addr, int len) {
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*** Using a 32 bit accumulator (sum), we add sequential 16 bit words to it, 
    and at the end, fold back all the carry bits from the top 16 bits into the 
    lower 16 bits. ****/
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    // mop up an odd byte, if necessary 
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    // add back carry outs from top 16 bits to low 16 bits 
    sum = (sum >> 16) + (sum & 0xffff);     // add hi 16 to low 16 
    sum += (sum >> 16);                     // add carry 
    answer = ~sum;                          // truncate to 16 bits 
    return (answer);
}

// Find max RTT time
long int max(long int x, long int y) {
    if (x >= y) return x;
    return y;
}

// Find min RTT time
long int min(long int x, long int y) {
    if (x <= y)return x;
    return y;
}

// Allocate memory for an array of chars.
char *allocate_strmem (int len) {
    void *tmp;
    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (char *) malloc (len * sizeof (char));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (char));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit (EXIT_FAILURE);
    }
}

void printTitle() {
 printf("\n");

printf(" ____                                                 __                  \n");                   
printf("/\\  _`\\                                              /\\ \\                 \n");  
printf("\\ \\,\\L\\_\\  _____      __    ___     ___     __   _ __\\ \\/      ____       \n");  
printf(" \\/_\\__ \\ /\\ '__`\\  /'__`\\/' _ `\\  /'___\\ /'__`\\/\\`'__\\/      /',__\\      \n");  
printf("   /\\ \\L\\ \\ \\ \\L\\ \\/\\  __//\\ \\/\\ \\/\\ \\__//\\  __/\\ \\ \\/       /\\__, `\\     \n");  
printf("   \\ `\\____\\ \\ ,__/\\ \\____\\ \\_\\ \\_\\ \\____\\ \\____\\ \\_\\       \\/\\____/     \n");  
printf("    \\/_____/\\ \\ \\/  \\/____/\\/_/\\/_/\\/____/\\/____/ \\/_/        \\/___/      \n");  
printf("             \\ \\_\\                                                        \n");  
printf("              \\/_/                                                        \n");  
printf("         ____        ______      __  __      ____                         \n");  
printf("        /\\  _`\\     /\\__  _\\    /\\ \\/\\ \\    /\\  _`\\                       \n");  
printf("        \\ \\ \\L\\ \\   \\/_/\\ \\/    \\ \\ `\\ \\   \\ \\ \\L\\_\\                     \n");  
printf("         \\ \\ ,__/      \\ \\ \\     \\ \\ , ` \\   \\ \\ \\L_L                     \n");  
printf("          \\ \\ \\/        \\_\\ \\__   \\ \\ \\`\\ \\   \\ \\ \\/, \\                   \n");  
printf("           \\ \\_\\        /\\_____\\   \\ \\_\\ \\_\\   \\ \\____/                   \n");  
printf("            \\/_/        \\/_____/    \\/_/\\/_/    \\/___/                    \n");  
printf("                                                                          \n");  
                                                        
}





