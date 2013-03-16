#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <stdlib.h>

#include "ip-handler.h" /* prototypes */
#include "ethernet.h" /* EthernetFrame */
#include "sr_router.h" /* sr_instance */
#include "sr_protocol.h" /* sr_ip_hdr_t */
#include "router-utils.h" /* get_int, get_short, get_char */
#include "sr_utils.h" /* checksum */
#include "sr_rt.h" /* routing table */

using namespace std;




struct sr_if * router_ip_match(struct sr_if * list, uint32_t ip){
	if(list){
		if(ip==list->ip){
			return list;
		}else{
			return interface_match(list->next, ip);
		}
	}
	return NULL;
}


void create_icmp_packet(struct sr_instance* sr, sr_icmp_hdr_t *packet, unsigned int len, uint8_t type, uint8_t code) { //Still needs work........................
	sr_icmp_t3_hdr_t *newICMP;
	//unsigned int ICMPlen;
	
	//ICMP Type: Echo Reply
	if(type == 0) {
		//ICMPlen = len - ((packet->ip_hl)*4);
		newICMP = (sr_icmp_t3_hdr_t *)malloc(len);
	}
	
	//ICMP Type: Time Exceeded, Unreachable
	else if(type == 11 || type == 3) {
		newICMP = (sr_icmp_t3_hdr_t *)malloc(sizeof(sr_icmp_t3_hdr_t));
	}
	
	else {
		printf("ERROR: Cannot create ICMP packet - unrecognized type.\n");
		return;
	}
	
	free(newICMP);
	
	

void send_icmp_packet() { //INCOMPLETE
}


void send_ip_packet() {
	//Daniel's code goes here
}


void handle_ip_packet(struct sr_instance * sr, EthernetFrame * frame, char * interface) {

	uint8_t *IP_payload = frame->GetPayload();
	int len = frame->PayloadLength();
	
	sr_ip_hdr_t *packet = (sr_ip_hdr_t *)IP_payload;
	
	
	// Check if packet has at least the minval for IHL
   if (len < 20) {
		printf("ERROR: Incomplete IP packet received.\n");
		return;
	}
	
	// Checksum verification
	uint16_t oldCheckSum = packet->ip_sum;
	packet->ip_sum = 0;
	uint16_t newCheckSum = cksum(packet,(packet->ip_hl)*4);
	if (oldCheckSum != newCheckSum) {
		printf("ERROR: Corrupted packet - incorrect checksum.\n");
		return;
	}

	// Check destination IP against interfaces (destined to router?)
	
	struct sr_if * i_entry = router_ip_match(sr->if_list, packet->ip_dst);
	
	if(i_entry){
		printf("Kunaal's Section\n");
		if (packet->ip_p == ip_protocol_icmp) {
			sr_icmp_hdr_t *icmp_packet =(sr_icmp_hdr_t *)((uint8_t *)packet + ((packet->ip_hl)* 4));
			int icmpPacketLen = len - ((packet->ip_hl)* 4);
			
			//ICMP Type: Echo Request
			if ((icmp_packet->icmp_type != 8) || (icmp_packet->icmp_code != 0)) {
				printf("ERROR: ICMP-Not a valid echo request/reply.\n");
				return;
			}
			else create_icmp_packet(sr, icmp_packet, icmpPacketLen, 0, 0);
		}
		else {
			printf("UDP/TCP\n");
		
		}
	}
	else printf("Daniel's Section\n");
		
	/*****************************************************************/printf("###: Checkpoint 0\n");
	
}




