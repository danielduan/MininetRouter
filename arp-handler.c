#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>
#include <string>
#include <stdint.h>
#include <stdlib.h>

#include "ip-handler.h" /*handle_ip_packet*/
#include "arp-handler.h" /* prototypes */
#include "ethernet.h" /* EthernetFrame */
#include "sr_router.h" /* sr_instance */
#include "sr_protocol.h" /* sr_arp_hdr_t */
#include "router-utils.h" /* get_int, get_short, get_char */
#include "sr_rt.h" /* routing table */
using namespace std;

uint8_t * new_broadcast(sr_arp_hdr_t * arp){
	uint8_t * response = new uint8_t[42];
	unsigned char tmp0[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	memcpy(response, tmp0, 6);
	memcpy(response+6, arp->ar_sha, 6);
	uint8_t tmp1[] = {0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01};
	memcpy(response+12, tmp1, 10);
	memcpy(response+22, arp->ar_sha, 6);
	memcpy(response+28, (void *)(&(arp->ar_sip)), 4);
	unsigned char tmp2[] = {0x00,0x00,0x00,0x00,0x00,0x00};
	memcpy(response+32, tmp2, 6);
	memcpy(response+38, (void *)(&(arp->ar_tip)), 4);
	return response;
}

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

sr_arp_hdr_t * new_arp_packet(uint8_t * payload){
	sr_arp_hdr_t * arp = new sr_arp_hdr_t;
	memset(arp, 0, sizeof(sr_arp_hdr_t));
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
}

void request_arp(struct sr_instance * sr, struct sr_arpreq * req){
	if(difftime(time(NULL), req->sent) > 1.0){
		struct sr_if* interface = NULL;
		struct sr_rt * entry = longest_match(sr->routing_table, flip_ip(req->ip)); // flips ip
		if(entry){
			interface = interface_search_by_name(sr->if_list, entry->interface);
			if(interface==NULL){
				cerr << "ERROR: Routing table tried to use non-existing interface: "<< entry->interface << endl;
				return;
			}
		}else{
			cerr << "ERROR: Routing table contained unreachable address: "<< req->ip << endl;
			return;
		}
		sr_arp_hdr_t arp;
		arp.ar_tip = flip_ip(req->ip);
		memcpy(arp.ar_sha, interface->addr, 6);
		arp.ar_sip = interface->ip;
		uint8_t * request = new_broadcast(&arp);
		cout << "ARP: Requesting, IP: "<< arp.ar_tip << ", Try number: " << req->times_sent << endl;
		cout << "Interface: "<< interface->name << endl;
		sr_send_packet(sr, request, 42, interface->name);
		req->sent = time(NULL);
		req->times_sent++;
		delete request;
	}else{
		cerr << "ARP: Tried too soon, IP: " << req->ip << endl;
	}
}

void empty_request_queue(struct sr_instance * sr, struct sr_arpreq * req){
	cout << "ARP: Processing packet queue" << endl;
	struct sr_packet * packet;
	EthernetFrame * frame;
	for (packet = req->packets; packet != NULL; packet = packet->next) {
		frame = new EthernetFrame(packet->buf, packet->len);
		route_packet(sr, frame, packet->iface);
		delete frame;
	}
	sr_arpreq_destroy(&sr->cache, req);
}

void handle_arp_packet(struct sr_instance * sr, EthernetFrame * frame, char * interface){
	sr_arp_hdr_t * arp = new_arp_packet(frame->GetPayload());
	if(!arp){
		cerr << "ARP: Couldn't allocate memory" << endl;
		return;
	}
	if(arp->ar_op==1){
		cout << "ARP: Request" << endl;
		struct sr_if * i_entry = interface_match(sr->if_list, arp->ar_tip);
		if(i_entry){
			cout << "ARP: Destined to router interface" << endl;
			memcpy(arp->ar_tha, arp->ar_sha, 6);
			arp->ar_tip = arp->ar_sip;
			memcpy(arp->ar_sha, i_entry->addr, 6);
			arp->ar_sip = i_entry->ip;
			uint8_t * response = new_arp_response(arp);
			cout << "ARP: Responding" <<endl;
			sr_send_packet(sr, response, 42, i_entry->name);
			delete response;
		}else{
			cerr << "ARP is not for any of the router interfaces" << endl;
		}
	}else if(arp->ar_op==2){
		cout << "ARP: Response" << endl;
		struct sr_arpreq * req = sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip);
		if(req){
			empty_request_queue(sr, req);
		}else{
			cout << "Source IP: " << arp->ar_sip <<endl;
			cerr << "ARP: Response dind't find a packet queue" << endl;
		}
	}else{
		cerr << "ARP: Invalid OP code"<< endl;
	}
	delete arp;
}

void require_arp(struct sr_instance * sr,  struct sr_arpreq * req){
	struct sr_arpentry * entry = sr_arpcache_lookup(&(sr->cache), req->ip);
	if(entry){
		empty_request_queue(sr, req);
		delete entry;
	}else{
		if(req->times_sent>=5){
			cerr << "ARP: timeout, request already sent five times" << endl;
			// struct packet_t * new_icmp_packet(packet_t, uint8_t, uint8_t);
			sr_arpreq_destroy(&sr->cache, req);
		}else{
			request_arp(sr, req);
		}
	}
}



