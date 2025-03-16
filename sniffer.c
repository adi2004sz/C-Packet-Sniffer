#include "sniffer.h"
#include "packet_handler.h"

pcap_t *initialize_sniffer(const char *interface, const char *filter_exp, pcap_dumper_t **dumper) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return NULL;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    *dumper = pcap_dump_open(handle, "captured_packets.pcap");
    if (*dumper == NULL) {
        fprintf(stderr, "Error opening output file: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    return handle;
}

void start_sniffing(pcap_t *handle, pcap_dumper_t *dumper) {
    pcap_loop(handle, 0, packet_handler, (u_char *)dumper);
}

void cleanup(pcap_t *handle, pcap_dumper_t *dumper) {
    pcap_dump_close(dumper);
    pcap_close(handle);
}
