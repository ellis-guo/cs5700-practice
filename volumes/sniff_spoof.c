#include <pcap.h>
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

void send_reply(struct in_addr src, struct in_addr dst,
                unsigned short id, unsigned short seq) {
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    struct ipheader  *ip   = (struct ipheader *)buffer;
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));

    ip->iph_ver      = 4;
    ip->iph_ihl      = 5;
    ip->iph_ttl      = 64;
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_sourceip = dst;  // swap src/dst
    ip->iph_destip   = src;
    ip->iph_len      = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

    icmp->icmp_type   = 0;   // echo reply
    icmp->icmp_code   = 0;
    icmp->icmp_id     = id;
    icmp->icmp_seq    = seq;
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = checksum((unsigned short *)icmp, sizeof(struct icmpheader));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr   = ip->iph_destip;

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    sendto(sd, buffer, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&sin, sizeof(sin));
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    struct ipheader   *ip   = (struct ipheader *)(packet + 14);
    struct icmpheader *icmp = (struct icmpheader *)(packet + 14 + ip->iph_ihl * 4);

    if (icmp->icmp_type == 8) {  // echo request
        printf("Caught request from %s, sending reply...\n",
               inet_ntoa(ip->iph_sourceip));
        send_reply(ip->iph_sourceip, ip->iph_destip,
                   icmp->icmp_id, icmp->icmp_seq);
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    handle = pcap_open_live("br-2b06a793de6e", BUFSIZ, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
