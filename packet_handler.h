#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <pcap.h>

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

#endif
