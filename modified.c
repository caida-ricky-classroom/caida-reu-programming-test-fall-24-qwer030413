#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
//This is a test
int main(int argc, char *argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	const unsigned char *packet;
        struct pcap_pkthdr header;
	struct iphdr *ip_header;
	int packet_count = 0;
			
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
		return 1;
	}

	handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL) {
        	fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
		return 1;
	}
	while ((packet = pcap_next(handle, &header)) != NULL) {
//		if(header.caplen < sizeof(struct ethhdr) + sizeof(struct iphdr)){
			
//		}
		ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
		struct in_addr dest_addr;
		dest_addr.s_addr = ip_header->daddr;
		printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(dest_addr));
	}
	pcap_close(handle);
        return 0;
}