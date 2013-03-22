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

/*
 * Structure of an internet header, naked of options.
 */
/*struct sr_ip_hdr_mmmmm
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		header length 
    unsigned int ip_v:4;		 version 
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		 version 
    unsigned int ip_hl:4;		 header length 
#else
#error "Byte ordering ot specified " 
#endif 
    uint8_t ip_tos;			 type of service 
    uint16_t ip_len;			 total length 
    uint16_t ip_id;			 identification 
    uint16_t ip_off;			 fragment offset field 
#define	IP_RF 0x8000			 reserved fragment flag 
#define	IP_DF 0x4000			 dont fragment flag 
#define	IP_MF 0x2000			 more fragments flag 
#define	IP_OFFMASK 0x1fff		 mask for fragmenting bits 
    uint8_t ip_ttl;			 time to live 
    uint8_t ip_p;			 protocol 
    uint16_t ip_sum;			 checksum 
    uint32_t ip_src, ip_dst;	 source and dest address 
  } __attribute__ ((packed)) ;*/
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
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *) raw_ip->packet;
	//uint8_t * icmp_payload = (uint8_t *)(raw_ip->packet+20+8);
	uint8_t empty[] = {0x00, 0x00};
	uint8_t * ret;
	uint16_t len;
	switch(type){
		case 0:{
			cout << "IP length: "<< ip_header-> ip_len << endl; 
			len = (uint16_t) (ntohs(ip_header -> ip_len) - 20);// size of IP payload
			cout << "Length of IP payload: " << len << endl;
			ret = new uint8_t[len];
			memcpy(ret, (void *)(&type), 1);
			memcpy(ret+1, (void *)(&code), 1);
			memcpy(ret+2, empty, 2);
			memcpy(ret+4, raw_ip->packet+20+4, 2);
			memcpy(ret+6, raw_ip->packet+20+6, 2);
			memcpy(ret+8, raw_ip->packet+20+8, len-8);
			uint16_t tmp = cksum(ret, len);
			memcpy(ret+2, (void *)(&tmp), 2);
		}
		break;
		case 8:{}
		break;
		case 3:{}
		break;
		case 4:{}
		break;
	}
	cout << "Their payload" << endl;
	print_hex(raw_ip->packet, raw_ip->length);
	struct packet_t * str_ret = new struct packet_t;
	str_ret -> packet = ret;
	str_ret -> length = len;//14
	return str_ret;
}
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

struct packet_t * new_ip_packet(struct sr_instance * sr, sr_ip_hdr_t * ip_packet, packet_t * icmp_packet, char * interface){
	uint16_t len_i = 20+icmp_packet->length;
	struct sr_if * entry = interface_search_by_name(sr->if_list, interface);
	uint8_t * the_packet = new uint8_t[len_i];
	
	uint32_t new_dest = ip_packet->ip_src; // assuming its 
	uint32_t new_source = entry->ip;
	
	cout << "Len i: " << len_i << endl;
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
	uint16_t tmp = cksum(the_packet, len_i);
	memcpy(the_packet+10, (void *)(&tmp), 2);
	
	struct packet_t * str_ret = new struct packet_t;
	str_ret -> packet = the_packet;
	str_ret -> length = len_i;
	cout << "New IP header length: " <<  str_ret -> length << endl;
	return str_ret;
}


void send_icmp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint8_t type, uint8_t code) {
 
  /* ethernet header */
  /* ip header */
  sr_ip_hdr_t * ip_header = (sr_ip_hdr_t*)(packet);
  /* outgoing interface */
  struct sr_if* out_if = sr_get_interface(sr, interface); 
  
  uint8_t icmp_len;
  uint8_t payload_len;
  /* echo reply */
  if (type == 0) {
    icmp_len = ntohs(ip_header->ip_len) - sizeof(sr_ip_hdr_t );    
    payload_len = icmp_len - sizeof(sr_icmp_hdr_t) - 4;
  } else {
    icmp_len = sizeof(sr_icmp_t3_hdr_t);
    payload_len = ICMP_DATA_SIZE;
  }
  
  uint8_t total_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+icmp_len;
  uint8_t* icmp_pkt = (uint8_t*)malloc(total_len); 
   
  /* generate ICMP header */  
  sr_icmp_t3_hdr_t* icmp_header = (sr_icmp_t3_hdr_t*)(icmp_pkt+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
  
  memcpy(icmp_header, ip_header+1, icmp_len);
  icmp_header->icmp_type = type;
  icmp_header->icmp_code = code;    
  icmp_header->icmp_sum = 0;
  /* not echo reply */
  if (type!=0) {
    memcpy(icmp_header->data, ip_header, payload_len);
  }
  icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_t3_hdr_t)); 
  
  /* generate IP packet */
  sr_ip_hdr_t* new_ip_header = (sr_ip_hdr_t*)(icmp_pkt+sizeof(sr_ethernet_hdr_t));
  memcpy(new_ip_header, ip_header, sizeof(sr_ip_hdr_t));
  uint16_t pk_len = sizeof(sr_ip_hdr_t)+ icmp_len;
  new_ip_header->ip_len = htons(pk_len);
  new_ip_header->ip_src = out_if->ip;
  new_ip_header->ip_dst = ip_header->ip_src;
  new_ip_header->ip_ttl = 0x40;
  new_ip_header->ip_p = ip_protocol_icmp;
  //new_ip_header->ip_dst = ntohl(new_ip_header->ip_dst);
  
  cout << "IP Header src: " << new_ip_header->ip_src << endl;
  cout << "IP Header dest: " << new_ip_header->ip_dst << endl;
  
  new_ip_header->ip_sum = 0;
  new_ip_header->ip_sum = cksum(new_ip_header, sizeof(sr_ip_hdr_t));  

  /* generate Ethernet frame*/
  sr_ethernet_hdr_t* new_eth_header = (sr_ethernet_hdr_t*)icmp_pkt;
  new_eth_header->ether_type = htons(ethertype_ip);  
  
  /* send ICMP packet*/
  EthernetFrame * frame = new EthernetFrame(icmp_pkt, total_len);
  send_ip_packet(sr, frame, total_len, interface, true);
  delete frame;
  /* free extra memory */
  free(icmp_pkt);
}

void send_ip_packet(struct sr_instance* sr,
        EthernetFrame * frame,
        unsigned int len,
        char* interface,
        bool ICMP) {
        
	uint8_t * packet = frame->GetPayload();
	sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t*)packet;
	/* check dest IP in routing table */
	uint32_t next_hop_ip = get_int(packet+4*4);
	cout << "Sending to IP: " << next_hop_ip << endl;
  	struct sr_rt* routing_index = longest_match(sr->routing_table, next_hop_ip);//check_routingtable(sr, next_hop_ip); // flips
  	if(routing_index){
		cout << "Routing index found" << endl;
		char * next_hop_if = routing_index->interface;
		/* check ARP in cache */
		struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);// flip because of routing entry
		if (entry){ // && entry->valid
			struct sr_if* out_if = sr_get_interface(sr, next_hop_if);
			/* update ethernet header */
			memcpy(eth_header->ether_shost, out_if->addr, ETHER_ADDR_LEN);
			memcpy(eth_header->ether_dhost, entry->mac, ETHER_ADDR_LEN); 
			/* send packet to next hop*/ 
			sr_send_packet(sr, frame->GetPacket(), frame->PayloadLength()+14, next_hop_if);
		}else{
			/* save packet in the request queue */
			cout << "send_ip_packet: No ARP, queueing and requesting" << next_hop_ip << endl;
			//frame->print_hex();
			struct sr_arpreq * req =  sr_arpcache_queuereq(&sr->cache, next_hop_ip, frame->GetPacket(), frame->PayloadLength()+14, next_hop_if);
			cout << "Packet queued"<< endl;
			require_arp(sr, req);
		}
		free(entry);
	} else {
		cout << "No route" << endl;
		if (!ICMP) {
			cout << "Sending ICMP Host Unreachable" << endl;
			send_icmp_packet(sr, packet, len, interface, 3, 0);
		}else{
			cout << "send_ip_packet: BAD CALL, Nothing to do" << endl;
		}
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
void route_packet(struct sr_instance * sr, sr_ip_hdr_t * packet){
	cout << "Routing to IP: " << ip_to_string(packet->ip_dst) << endl;
	cout << "Trying longest match" << endl;
	struct sr_rt* r_entry = longest_match(sr->routing_table, packet->ip_dst);
	struct sr_arpentry * a_entry;
	if(r_entry){
		cout << "Match found, trying ARP cache" << endl;
		 a_entry = sr_arpcache_lookup(&sr->cache, packet->ip_dst);
		if(a_entry){
			cout << "ARP entry found, sending" << endl;
		}else{
			cerr << "No ARP entry" << endl;
		}
	}else{
		cerr << "ERROR: No routing entry found" << endl;
		cout << "Sending ICMP Host Unreachable" << endl;
		a_entry = sr_arpcache_lookup(&sr->cache, packet->ip_src);
		if(a_entry){
			cout << "ARP entry found, sending ICMP" << endl;
			//uint8_t * ip_icmp = new_icmp_packet(packet, 3, 0);
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
   if (len < 20) {
		printf("ERROR: Incomplete IP packet received.\n");
		return;
	}else{
		cout << "IP: Correct length"<< endl;
	}
	uint16_t oldCheckSum = packet->ip_sum;
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
			//int icmpPacketLen = len - ((packet->ip_hl)* 4);
			
			//ICMP Type: Echo Request
			if ((icmp_packet->icmp_type != 8) || (icmp_packet->icmp_code != 0)) {
				printf("ERROR: ICMP-Not a valid echo request/reply.\n");
				return;
			}
			else{
				struct packet_t * icmp = new_icmp_packet(&raw_ip, 0, 0);
				struct packet_t * ip_packet = new_ip_packet(sr, packet, icmp, interface);
				// uint8_t * dest, uint8_t * source, 
				EthernetFrame * the_frame = new EthernetFrame(frame->GetSrcAddress(), frame->GetDestAddress(), ip_packet->packet, ip_packet->length, IP_PACKET);
				sr_send_packet(sr, the_frame->GetPacket(), the_frame->PayloadLength()+14, interface);
				//print_hex(the_frame->GetPacket(), the_frame->PayloadLength()+14);
				//send_icmp_packet(sr, IP_payload, len, interface, 0, 0);
			}
		}
		else {
			printf("UDP/TCP\n");
		
		}
	}
	else{
		cout << "Not for the router, routing" << endl;
		route_packet(sr, packet);
		//send_ip_packet(sr, frame, len, interface, false);
	}
	
}




