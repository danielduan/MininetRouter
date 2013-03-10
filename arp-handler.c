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
#include "router-utils.h" /* get_int, get_short, get_char */
#include "sr_rt.h" /* routing table */
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

uint8_t * new_arp_response(sr_arp_hdr_t * arp){
	uint8_t * response = new uint8_t[42];
	memcpy(response, arp->ar_tha, 6);
	memcpy(response+6, arp->ar_sha, 6);
	uint8_t tmp1[] = {0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02};
	memcpy(response+12, tmp1, 10);
	memcpy(response+22, arp->ar_sha, 6);
	memcpy(response+28, (void *)(&(arp->ar_sip)), 4);
	memcpy(response+32, arp->ar_tha, 6);
	memcpy(response+38, (void *)(&(arp->ar_tip)), 4);
	return response;
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

/*
struct sr_if
{
  char name[sr_IFACE_NAMELEN];
  unsigned char addr[ETHER_ADDR_LEN];
  uint32_t ip;
  uint32_t speed;
  struct sr_if* next;
};
*/

void handle_arp(struct sr_instance * sr , EthernetFrame * frame, char * interface){
	sr_arp_hdr_t * arp = new_arp_packet(frame);
	if(!arp){
		cerr << "ARP: Couldn't allocate memory" << endl;
		return;
	}
	if(arp->ar_op==1){
		cout << "ARP: Request" << endl;
		struct sr_if * i_entry = interface_match(sr->if_list, arp->ar_tip);
		if(i_entry){
			cout << "ARP: Destined to router interface" << endl;
			arp->ar_op = 2;
			memcpy(arp->ar_tha, arp->ar_sha, 6);
			arp->ar_tip = flip_ip(arp->ar_sip);
			memcpy(arp->ar_sha, i_entry->addr, 6);
			arp->ar_sip = i_entry->ip;
			uint8_t * response = new_arp_response(arp);
			cout << "ARP: Responding"<<endl;
			sr_send_packet(sr, response, 42, i_entry->name);
		}
	}else if(arp->ar_op==2){
		cout << "ARP: Response" << endl;
	}else{
		cerr << "ARP: Invalid OP code"<< endl;
	}
	delete arp;
}
