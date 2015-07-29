#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
	struct pcap_pkthdr header;
	const u_char *cur_packet;

	pcap_t *handle;
	handle = pcap_open_offline(argv[1], errbuf); // Open pcap file

	// Error check handle here

	while (cur_packet = pcap_next(handle, &header))
}