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

/*
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
}	
	*/
	
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
  new_ip_header->ip_dst = ntohl(new_ip_header->ip_dst);
  
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
  //uint32_t dest = get_int(frame->GetPayload()+4*4);
  //sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(eth_header+1);  
  /* check dest IP in routing table */
  cout << "IP: " << ntohl(get_int(packet+4*4)) << endl;
  struct sr_rt* routing_index = check_routingtable(sr, ntohl(get_int(packet+4*4)));
  if (routing_index) {
  	cout << "Route index" << endl;
    uint32_t next_hop_ip = ntohl(routing_index->gw.s_addr);
    char* next_hop_if = routing_index->interface;
    /* check ARP in cache */
    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
    if (entry ) { // && entry->valid
      struct sr_if* out_if = sr_get_interface(sr, next_hop_if);
      /* update ethernet header */
      memcpy(eth_header->ether_shost, out_if->addr, ETHER_ADDR_LEN);
      memcpy(eth_header->ether_dhost, entry->mac, ETHER_ADDR_LEN); 
      /* send packet to next hop*/ 
      sr_send_packet(sr, packet, len, next_hop_if);
    } else {
      /* save packet in the request queue */
      cout << "IP next hop: " << next_hop_ip<< endl;
      struct sr_arpreq * req =  sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, next_hop_if);
      cout << "Packet queued"<< endl;
      require_arp(sr, req);
    }
    free(entry);
  } else {
  		cout << "No route" << endl;
    /* ICMP destination unreachable*/
    if (!ICMP) {
    cout << "Sending ICMP Unreachable" << endl;
    	
      send_icmp_packet(sr, packet, len, interface, 3, 0);
    }else{
    	cout << "No ICMP" << endl;
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
		/* printf("Kunaal's Section\n");
		if (packet->ip_p == ip_protocol_icmp) {
			sr_icmp_hdr_t *icmp_packet =(sr_icmp_hdr_t *)((uint8_t *)packet + ((packet->ip_hl)* 4));
			int icmpPacketLen = len - ((packet->ip_hl)* 4);
			
			//ICMP Type: Echo Request
			if ((icmp_packet->icmp_type != 8) || (icmp_packet->icmp_code != 0)) {
				printf("ERROR: ICMP-Not a valid echo request/reply.\n");
				return;
			}
			else send_icmp_packet(sr, icmp_packet, icmpPacketLen, interface, 0, 0);
		}
		else {
			printf("UDP/TCP\n");
		
		}*/
	}
	else{
		cout << "Not for the router" << endl;
		send_ip_packet(sr, frame, len, interface, false);
	}
	
}




