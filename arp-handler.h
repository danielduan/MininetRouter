#ifndef _ARP_HANDLER_
#define _ARP_HANDLER_

#include "ethernet.h" /* EthernetFrame */
#include "sr_router.h" /* sr_instance */
#include "sr_protocol.h" /* sr_arp_hdr_t */

/**
	handle_arp: handle all incoming ARP packets
*/
void handle_arp(struct sr_instance *, EthernetFrame *, char *);


/**
	get_arp_header: build a structure containing the parsed ARP packet 
*/
sr_arp_hdr_t * get_arp_header(EthernetFrame *);

#endif