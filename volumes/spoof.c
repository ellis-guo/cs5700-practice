#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct ipheader {
    unsigned char  iph_ihl:4, iph_ver:4;
    unsigned char  iph_tos;
    unsigned short iph_len;
    unsigned short iph_ident;
    unsigned short iph_frag;
    unsigned char  iph_ttl;
    unsigned char  iph_protocol;
    unsigned short iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

struct icmpheader {
    unsigned char  icmp_type;
    unsigned char  icmp_code;
    unsigned short icmp_chksum;
    unsigned short icmp_id;
    unsigned short icmp_seq;
};

unsigned short checksum(unsigned short *buf, int len) {
    unsigned int sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main() {
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    struct ipheader *ip = (struct ipheader *)buffer;
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));

    // Fill IP header
    ip->iph_ver    = 4;
    ip->iph_ihl    = 5;
    ip->iph_ttl    = 64;
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");  // spoofed source
    ip->iph_destip.s_addr   = inet_addr("10.9.0.5"); // Host A
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

    // Fill ICMP header
    icmp->icmp_type   = 8; // echo request
    icmp->icmp_code   = 0;
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = checksum((unsigned short *)icmp, sizeof(struct icmpheader));

    // Send
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr   = ip->iph_destip;

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) { perror("socket"); return -1; }

    int one = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    sendto(sd, buffer, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin, sizeof(sin));
    printf("Spoofed packet sent!\n");
    return 0;
}
