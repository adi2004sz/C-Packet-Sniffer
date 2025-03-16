#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>

pcap_t *initialize_sniffer(const char *interface, const char *filter_exp, pcap_dumper_t **dumper);

void start_sniffing(pcap_t *handle, pcap_dumper_t *dumper);

void cleanup(pcap_t *handle, pcap_dumper_t *dumper);

#endif
