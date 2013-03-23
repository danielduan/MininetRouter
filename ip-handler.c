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
#include "arp-handler.h" /* arp request */
#include "sr_arpcache.h" /* arp cache */

using namespace std;

char * ip_to_string(uint32_t ip){
	struct in_addr addr;
	addr.s_addr = ip;
	return inet_ntoa(addr);
}


struct sr_if * router_ip_match(struct sr_if * list, uint32_t ip){
	cout << "Matching IP to router interfaces: " << ip << endl;
	return interface_match(list, ip); // flips
}

uint32_t to_little(uint32_t ip){
	return (uint32_t)(((ip&0xFF000000)>>8)|((ip&0xFF0000)<<8)|((ip&0xFF00)>>8)|((ip&0xFF)<<8));
}

struct packet_t{
	uint8_t * packet;
	uint16_t length; // little
};

void print_hex(uint8_t * rawPacket, size_t payloadLength) {
    for(size_t i = 0; i < payloadLength; i++) {
        printf("%02x ", rawPacket[i]);
        if(i&&i%32==0) printf("\n");
    }
    printf("\n");
}

struct packet_t * new_icmp_packet(packet_t * raw_ip, uint8_t type, uint8_t code) {
	cout << "RAW IP PACKET" << endl;
	print_hex(raw_ip->packet, raw_ip->length);
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *) raw_ip->packet;
	uint8_t empty[] = {0x00, 0x00};
	uint8_t * ret;
	uint16_t tmp;
	uint16_t len;
	switch(type){
		case 0:{
			len = (uint16_t) (ntohs(ip_header -> ip_len) - 20);
			ret = new uint8_t[len];
			memcpy(ret, (void *)(&type), 1);
			memcpy(ret+1, (void *)(&code), 1);
			memcpy(ret+2, empty, 2);
			memcpy(ret+4, raw_ip->packet+20+4, 2);
			memcpy(ret+6, raw_ip->packet+20+6, 2);
			memcpy(ret+8, raw_ip->packet+20+8, len-8);
			uint16_t tmp = cksum(ret, len);
			cout << "ICMP Checksum: " << tmp << endl;
			memcpy(ret+2, (void *)(&tmp), 2);
		}
		break;
		case 8:{
			
		}
		break;
		case 11:
		case 3:{
			len = 20+8+8;
			ret = new uint8_t[len];
			memcpy(ret, (void *)(&type), 1);
			memcpy(ret+1, (void *)(&code), 1);
			memcpy(ret+2, empty, 2);
			memcpy(ret+4, empty, 2);
			memcpy(ret+6, empty, 2);
			memcpy(ret+8, raw_ip->packet, 20);
			memcpy(ret+28, raw_ip->packet+20, 8);
			tmp = cksum(raw_ip->packet, 20);
			memcpy(ret+8+10, (void *)(&tmp), 2);
			
			tmp = cksum(ret, len);
			memcpy(ret+2, (void *)(&tmp), 2);
		}
		break;
		case 4:{}
		break;
	}
	struct packet_t * str_ret = new struct packet_t;
	str_ret -> packet = ret;
	str_ret -> length = len;
	return str_ret;
}

struct packet_t * new_ip_packet(struct sr_instance * sr, sr_ip_hdr_t * ip_packet, packet_t * icmp_packet, char * interface){
	uint16_t len_i = 20+icmp_packet->length;
	struct sr_if * entry = interface_search_by_name(sr->if_list, interface);
	uint8_t * the_packet = new uint8_t[len_i];
	
	uint32_t new_dest = ip_packet->ip_src; // assuming its 
	uint32_t new_source = entry->ip;
	
	uint8_t part1[] = {0x45, 0x00,
						(uint8_t)((len_i&0xFF00)>>8), (uint8_t)(len_i&0xFF),  // check endian
						0x00, 0x00, // id to zero
						0x40, 0x00, // 
						0x24, // time to live
						0x01, // 
						0x00, 0x00,
						(uint8_t)(new_source&0xFF), (uint8_t)((new_source&0xFF00)>>8), (uint8_t)((new_source&0xFF0000)>>16),(uint8_t)((new_source&0xFF000000)>>24),
						(uint8_t)(new_dest&0xFF), (uint8_t)((new_dest&0xFF00)>>8), (uint8_t)((new_dest&0xFF0000)>>16),(uint8_t)((new_dest&0xFF000000)>>24)};
	
	memcpy(the_packet, part1, 20);
	memcpy(the_packet+20, icmp_packet->packet, icmp_packet->length);
	uint16_t tmp = cksum(the_packet, 20);
	memcpy(the_packet+10, (void *)(&tmp), 2);
	
	struct packet_t * str_ret = new struct packet_t;
	str_ret -> packet = the_packet;
	str_ret -> length = len_i;
	return str_ret;
}

void send_ip_packet(struct sr_instance* sr, EthernetFrame * frame, char * interface) {
    packet_t raw_ip;
	raw_ip.packet = frame->GetPayload();
	raw_ip.length = frame->PayloadLength();
	sr_ip_hdr_t *packet = (sr_ip_hdr_t *)frame->GetPayload();
	uint32_t next_hop_ip = get_int(frame->GetPayload()+4*4);
	cout << "Sending to IP: " << next_hop_ip << endl;
  	struct sr_rt* routing_index = longest_match(sr->routing_table, flip_ip(next_hop_ip));
  	if(routing_index){
  		struct sr_if * i_entry = interface_search_by_name(sr->if_list, routing_index->interface);
		cout << "Routing index found" << endl;
		struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
		if (entry){
			sr_ip_hdr_t * ip_packet = (sr_ip_hdr_t *)frame->GetPayload();
			ip_packet->ip_ttl--;
			if(ip_packet->ip_ttl<1){
				cerr << "========== TTL Exceded" << endl;
				entry = sr_arpcache_lookup(&sr->cache, packet->ip_src);
				packet->ip_dst =  flip_ip(i_entry->ip);
				struct packet_t * icmp = new_icmp_packet(&raw_ip, 11, 1);
				struct packet_t * ip_packet = new_ip_packet(sr, packet, icmp, interface);
				EthernetFrame * the_frame = new EthernetFrame(frame->GetSrcAddress(), 
																frame->GetDestAddress(), 
																ip_packet->packet, 
																ip_packet->length, 
																IP_PACKET);
				sr_send_packet(sr, the_frame->GetPacket(), the_frame->PayloadLength()+14, interface);
				if(the_frame)
					delete the_frame;
				if(ip_packet->packet)
					delete ip_packet->packet;
				if(ip_packet)
					delete ip_packet;
				if(icmp->packet)
					delete icmp->packet;
				if(icmp)
					delete icmp;
			}else{
				cout << "Sending packet now through interface " << interface <<endl;
				ip_packet -> ip_sum = 0;
				int correct;
				ip_packet -> ip_sum  = cksum(frame->GetPayload(),20);
				correct = ip_packet -> ip_sum;
				EthernetFrame * the_frame = new EthernetFrame(entry->mac,
															i_entry->addr,
															frame->GetPayload(),
															frame->PayloadLength(), 
															IP_PACKET);
															
				int new_chk = cksum(the_frame->GetPayload(), 20);
				if(new_chk!=correct){
					uint8_t * tmp_packet = the_frame->GetPayload();
					memcpy(tmp_packet+10, &(correct), 2);
				}
				sr_send_packet(sr, the_frame->GetPacket(), the_frame->PayloadLength()+14, interface);
				delete the_frame;
			}
		}else{
			struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache, 
										get_int(frame->GetPayload()+16), 
										frame->GetPacket(), 
										frame->PayloadLength()+14, 
										i_entry->name);
			require_arp(sr, req);
			cerr << "No MAC in cache" << endl;
		}
	} else {
		cerr << "No route, Need ICMP here" << endl;
	}
}

struct sr_rt* check_routingtable(struct sr_instance* sr, uint32_t ip) {
  struct sr_rt* rt_pt = sr->routing_table;
  struct sr_rt* routing_index = NULL;
  bool is_matched = false;
  while (rt_pt) {
    if ( ntohl(rt_pt->dest.s_addr) == (ip & rt_pt->mask.s_addr)) {
      if (is_matched) {
        if (ntohl(rt_pt->mask.s_addr) > ntohl(routing_index->mask.s_addr)) {
          routing_index = rt_pt;
        }
      } else {
        is_matched = true;
        routing_index = rt_pt;
      }
    }
    rt_pt = rt_pt->next;
  } 
  return routing_index;
}

struct sr_ip_hdr_bb{
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    uint16_t ip_sum;			/* checksum */
    uint32_t ip_src, ip_dst;	/* source and dest address */
};

//
void route_packet(struct sr_instance * sr, EthernetFrame * frame, char * interface){
	cout << "HEADER RECEIVED" << endl;
	uint8_t *IP_payload = frame->GetPayload();
	sr_ip_hdr_t *packet = (sr_ip_hdr_t *)IP_payload;
	packet_t raw_ip;
	raw_ip.packet = IP_payload;
	raw_ip.length = frame->PayloadLength();
	
	cout << "Routing to IP: " << ip_to_string(packet->ip_dst) << endl;
	cout << "Trying longest match" << endl;
	struct sr_rt* r_entry = longest_match(sr->routing_table, packet->ip_dst);
	struct sr_arpentry * a_entry;
	if(r_entry){
		interface = r_entry->interface;
		cout << "Match found, trying ARP cache" << endl;
		 a_entry = sr_arpcache_lookup(&sr->cache, flip_ip(packet->ip_dst));
		if(a_entry){
			cout << "ARP entry found, sending packet" << endl;
			send_ip_packet(sr, frame, interface);
		}else{
			cerr << "route_packet: No ARP entry" << endl;
			struct sr_if * i_entry = interface_search_by_name(sr->if_list, interface);
			if(i_entry){
				struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache, 
												get_int(frame->GetPayload()+16), 
												frame->GetPacket(), 
												frame->PayloadLength()+14, 
												i_entry->name);
				require_arp(sr, req);
			}else{
				cerr << "No interface to send requests" << endl;
			}
			
		}
	}else{
		cerr << "ERROR: No routing entry found" << endl;
		cout << "Sending ICMP Net Unreachable" << endl;
		a_entry = sr_arpcache_lookup(&sr->cache, packet->ip_src);
		if(a_entry){
			cout << "ARP entry found, sending ICMP" << endl;
			struct packet_t * icmp = new_icmp_packet(&raw_ip, 3, 0);
			struct packet_t * ip_packet = new_ip_packet(sr, packet, icmp, interface);
			EthernetFrame * the_frame = new EthernetFrame(frame->GetSrcAddress(), frame->GetDestAddress(), ip_packet->packet, ip_packet->length, IP_PACKET);
			sr_send_packet(sr, the_frame->GetPacket(), the_frame->PayloadLength()+14, interface);
			if(icmp -> packet)
			delete icmp -> packet;
			if(ip_packet -> packet)
			delete ip_packet -> packet;
			if(icmp)
			delete icmp;
			if(ip_packet)
			delete ip_packet;
			if(the_frame)
			delete the_frame;
		}else{
			cerr << "No ARP entry found for recently connected client" << endl;
		}
	}
}

void handle_ip_packet(struct sr_instance * sr, EthernetFrame * frame, char * interface) {
	cout << "Handling IP"<< endl;
	uint8_t *IP_payload = frame->GetPayload();
	int len = frame->PayloadLength();
	sr_ip_hdr_t *packet = (sr_ip_hdr_t *)IP_payload;
	packet_t raw_ip;
	raw_ip.packet = IP_payload;
	raw_ip.length = frame->PayloadLength();
	cout << "Packet from client" << endl;
	frame->print_hex();
	cout << "b" << endl;
	print_hex(raw_ip.packet, raw_ip.length);
   if (len < 20) {
		printf("ERROR: Incomplete IP packet received.\n");
		return;
	}else{
		cout << "IP: Correct length"<< endl;
	}
	uint16_t oldCheckSum = packet->ip_sum;
	cout << oldCheckSum << endl;
	packet->ip_sum = 0;
	uint16_t newCheckSum = cksum(packet,(packet->ip_hl)*4);
	if (oldCheckSum != newCheckSum) {
		printf("ERROR: Corrupted packet - incorrect checksum.\n");
		return;
	}else{
		cout << "IP: Correct Checksum"<< endl;
	}
	struct sr_if * i_entry = router_ip_match(sr->if_list, flip_ip(packet->ip_dst));
	if(i_entry){
		if (packet->ip_p == ip_protocol_icmp) {
			sr_icmp_hdr_t * icmp_packet =(sr_icmp_hdr_t *)((uint8_t *)packet + ((packet->ip_hl)* 4));
			if ((icmp_packet->icmp_type != 8) || (icmp_packet->icmp_code != 0)) {
				printf("ERROR: ICMP-Not a valid echo request/reply.\n");
				return;
			}else{
				struct packet_t * icmp = new_icmp_packet(&raw_ip, 0, 0);
				struct packet_t * ip_packet = new_ip_packet(sr, packet, icmp, interface);
				EthernetFrame * the_frame = new EthernetFrame(frame->GetSrcAddress(), frame->GetDestAddress(), ip_packet->packet, ip_packet->length, IP_PACKET);
				sr_send_packet(sr, the_frame->GetPacket(), the_frame->PayloadLength()+14, interface);
				delete icmp -> packet;
				delete ip_packet -> packet;
				delete icmp;
				delete ip_packet;
				delete the_frame;
			}
		}
		else {
		struct sr_arpentry * a_entry;
			a_entry = sr_arpcache_lookup(&sr->cache, packet->ip_src);
		if(a_entry){
			cout << "ARP entry found, sending ICMP" << endl;
			struct packet_t * icmp = new_icmp_packet(&raw_ip, 3, 1);
			struct packet_t * ip_packet = new_ip_packet(sr, packet, icmp, interface);
			EthernetFrame * the_frame = new EthernetFrame(frame->GetSrcAddress(), frame->GetDestAddress(), ip_packet->packet, ip_packet->length, IP_PACKET);
			sr_send_packet(sr, the_frame->GetPacket(), the_frame->PayloadLength()+14, interface);
			if(icmp -> packet)
			delete icmp -> packet;
			if(ip_packet -> packet)
			delete ip_packet -> packet;
			if(icmp)
			delete icmp;
			if(ip_packet)
			delete ip_packet;
			if(the_frame)
			delete the_frame;
		}else{
			cerr << "No ARP entry found for recently connected client" << endl;
		}
		}
	}
	else{
		cout << "Not for the router, routing" << endl;
		route_packet(sr, frame, interface);
	}
	
}




