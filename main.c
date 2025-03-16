#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap.h>
#include "sniffer.h"
#include "packet_handler.h"

#define INTERFACE "enp0s3"
#define FILTER_EXPRESSION "tcp port 80 or udp port 53 or icmp"

pcap_t *handle = NULL;
pcap_dumper_t *dumper = NULL;

// Signal handler for clean exit
void handle_signal(int sig) {
    printf("\nTerminating....\n");
    if (handle) {
        pcap_breakloop(handle); // Stop pcap_loop
        cleanup(handle, dumper);
    }
    exit(0);
}

int main() {
    signal(SIGINT, handle_signal); // Capture Ctrl+C

    handle = initialize_sniffer(INTERFACE, FILTER_EXPRESSION, &dumper);
    if (!handle) return 1;

    printf("Sniffing on %s... Filtering: %s\n", INTERFACE, FILTER_EXPRESSION);
    printf("Press Ctrl+C to stop.\n");

    start_sniffing(handle, dumper); // Runs indefinitely

    cleanup(handle, dumper); // Clean up resources if loop exits
    return 0;
}
