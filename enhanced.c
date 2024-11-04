
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
int main(int argc, char *argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	const unsigned char *packet;
        struct pcap_pkthdr header;
	struct iphdr *ip_header;
	int packet_count = 0;
	//create array to count size of octets and set the initial values to 0.
	int octet_count[256];	
	memset(octet_count, 0, sizeof(octet_count));
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
		return 1;
	}

	handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL) {
        	fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
		return 1;
	}
	while ((packet = pcap_next(handle, &header)) != NULL){
		ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
		/* 
		Create a in_addr type variable named dest_addr which will store the destination IP adress
		tempoarily before converting it into a readable format.
		*/
		struct in_addr dest_addr;
		//get the destination IP address and store it in dest_addr. Use .s_addr is used to store IPv4 addresses in network byte order
		dest_addr.s_addr = ip_header->daddr;
		//inet_ntoa converts the address stored in dest_addr to a human readable string and we print it out using printf
		printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(dest_addr));
		//use ntohl to convert the network byte ordeer into host byte order, storing it in temp.
		unsigned char temp = ntohl(dest_addr.s_addr);
		//masking the IP address and extracting only the last octet value
		unsigned char last_octet = temp & 0xFF;
		//add the count to the occurance of that specific last octet
		octet_count[last_octet]++;
	}
	//print out the occurance count of octets
	printf("\nLast octet occurences:\n");
	for(int i = 0; i < 256; i++){
		if(octet_count[i] > 0){
			printf("Last octet %d: %d\n", i, octet_count[i]);
		}
	}
	pcap_close(handle);
        return 0;
}
