#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

struct ipheader {
    unsigned char  iph_ihl:4, iph_ver:4;
    unsigned char  iph_tos;
    unsigned short iph_len;
    unsigned short iph_ident;
    unsigned short iph_flag:3, iph_offset:13;
    unsigned char  iph_ttl;
    unsigned char  iph_protocol;
    unsigned short iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

//void got_packet(u_char *args, const struct pcap_pkthdr *header,
//                const u_char *packet)
//{
//    struct ipheader *ip = (struct ipheader *)(packet + 14);
//    printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
//    printf("To:   %s\n", inet_ntoa(ip->iph_destip));
//    printf("---\n");
//}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ipheader *ip = (struct ipheader *)(packet + 14);
    int ip_header_len = ip->iph_ihl * 4;
    
    // Skip Ethernet (14) + IP header + TCP header (20)
    const u_char *payload = packet + 14 + ip_header_len + 20;
    int payload_len = header->caplen - 14 - ip_header_len - 20;
    
    if (payload_len > 0) {
        printf("From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Data: ");
        for (int i = 0; i < payload_len; i++) {
            if (payload[i] >= 32 && payload[i] < 127)
                printf("%c", payload[i]);
        }
        printf("\n---\n");
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
   // char filter_exp[] = "icmp";
   // char filter_exp[] = "icmp and host 10.9.0.5 and host 10.9.0.6";
   // char filter_exp[] = "tcp and dst portrange 10-100";
    char filter_exp[] = "tcp and dst port 23";
    bpf_u_int32 net;

    handle = pcap_open_live("br-2b06a793de6e", BUFSIZ, 1, 1000, errbuf);
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}
