#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <stdlib.h>

#include "arp-handler.h" /* prototypes */
#include "ethernet.h" /* EthernetFrame */
#include "sr_router.h" /* sr_instance */
#include "sr_protocol.h" /* sr_arp_hdr_t */

using namespace std;

/**
struct sr_arp_hdr
{
    unsigned short  ar_hrd;             		format of hardware address   
    unsigned short  ar_pro;             		format of protocol address   
    unsigned char   ar_hln;             		length of hardware address   
    unsigned char   ar_pln;             		length of protocol address   
    unsigned short  ar_op;              		ARP opcode (command)         
    unsigned char   ar_sha[ETHER_ADDR_LEN];		sender hardware address      
    uint32_t        ar_sip;             		sender IP address            
    unsigned char   ar_tha[ETHER_ADDR_LEN];		target hardware address      
    uint32_t        ar_tip;             		target IP address            
} __attribute__ ((packed)) ;
*/

uint32_t get_int(uint8_t * point){
	return (uint32_t)((point[0]<<24)|(point[1]<<16)|(point[2]<<8)|(point[3]));
}

unsigned short get_short(uint8_t * point){
	return (unsigned short)((point[0]<<8)|(point[1]));
}

unsigned char get_char(uint8_t * point){
	return (unsigned char)(point[0]);
}

sr_arp_hdr_t * new_arp_packet(EthernetFrame * frame){
	sr_arp_hdr_t * arp = new sr_arp_hdr_t;
	memset(arp, 0, sizeof(sr_arp_hdr_t));
	uint8_t * payload = frame->GetPayload();
	arp->ar_hrd = get_short(payload);
	arp->ar_pro = get_short(payload+2);
	arp->ar_hln = get_char(payload+4);
	arp->ar_pln = get_char(payload+5);
	arp->ar_op = get_short(payload+6);
	memcpy(arp->ar_sha, payload+8,6);
	arp->ar_sip = get_int(payload+14);
	memcpy(arp->ar_tha, payload+18,6);
	arp->ar_tip = get_int(payload+24);
	return arp;
}//*/

int i=0;
void handle_arp(struct sr_instance * sr , EthernetFrame * frame, char * interface){
	sr_arp_hdr_t * arp = new_arp_packet(frame);
	if(arp->ar_op==1){
		cout << "ARP: Request" << hex << endl;
	}else if(arp->ar_op==2){
		cout << "ARP: Response" << endl;
	}else{
		cerr << "ARP: Invalid OP code"<< endl;
	}
	if(arp){
		delete arp;
	}
}
/*

Ethernet frame: Request
ff ff ff ff ff ff		Destination
9a 4b 8d 53 aa 98		Source
08 06					Ethertype

00 01 					hardware type
08 00 					protocol type (IP)
06 						Length of hardware address
04 						Length of protocol address
00 01					Opcode 1 (ARP request)
9a 4b 8d 53 aa 98		Sender's hardware address
0a 00 01 64 			Sender's protocol address (IP)
00 00 00 00 00 00 		Target hardware address
0a 00 01 01				Target protocol address (IP)

Ethernet frame: Response
9a 4b 8d 53 aa 98		Destination (Source of request)
00 90 27 3c 66 e1		Source (the host that's responding this request)
08 06					Ethertype
*00 01					Hardware type
08 00 					protocol type (IP)
06 						Length of hardware address
04 						Length of protocol address
00 02					Opcode 2 (ARP reply)
00 90 27 3c 66 e1		Senders hardware address
0a 00 01 01				Sendet's protocol address
9a 4b 8d 53 aa 98		Target hardware address
0a 00 01 64				Target protocol address
*/
