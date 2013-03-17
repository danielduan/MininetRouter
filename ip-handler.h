#ifndef _IP_HANDLER_
#define _IP_HANDLER_

#include "ethernet.h" /* EthernetFrame */
#include "sr_router.h" /* sr_instance */
#include "sr_protocol.h" /* sr_arp_hdr_t */

/**
	router_ip_match: checks where the destination IP is routed
*/
struct sr_if * router_ip_match(struct sr_if *, uint32_t);

/**
	handle_ip_packet: handle all incoming ARP packets
*/
//void create_icmp_packet(struct sr_instance* sr, sr_icmp_hdr_t *packet, unsigned int len, uint8_t type, uint8_t code);

void handle_ip_packet(struct sr_instance *, EthernetFrame *, char *);

void send_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, bool ICMP);

struct sr_rt* check_routingtable(struct sr_instance* sr, uint32_t ip);

#endif
