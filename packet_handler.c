#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "packet_handler.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    pcap_dump(user, header, packet); // Write to .pcap file

    struct ip *ip_header = (struct ip *)(packet + 14); // Ethernet header is 14 bytes

    printf("Captured packet - Source IP: %s, Destination IP: %s\n",
           inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        printf("TCP Packet - Source Port: %d, Destination Port: %d\n",
               ntohs(tcp_header->source), ntohs(tcp_header->dest));
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        printf("UDP Packet - Source Port: %d, Destination Port: %d\n",
               ntohs(udp_header->source), ntohs(udp_header->dest));
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        printf("ICMP Packet Detected\n");
    }

    printf("\n");
}
