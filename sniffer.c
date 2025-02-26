#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>


void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    
    printf("Captured Packet: %d bytes\n", header->len);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
        printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + (ip->ihl * 4));
            printf("Protocol: TCP, Src Port: %d, Dst Port: %d\n", ntohs(tcp->source), ntohs(tcp->dest));
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ethhdr) + (ip->ihl * 4));
            printf("Protocol: UDP, Src Port: %d, Dst Port: %d\n", ntohs(udp->source), ntohs(udp->dest));
        }
    }
    printf("---------------------------------------------\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }
    
    printf("Starting packet capture on eth0...\n");
    pcap_loop(handle, 10, packet_handler, NULL);
    
    pcap_close(handle);
    return 0;
}
