/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include "ethernet.h"
#include "router-utils.h"
#include "arp-handler.h"
#include "ip-handler.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

/**
struct sr_rt
{
    struct in_addr dest;
    struct in_addr gw;
    struct in_addr mask;
    char   interface[sr_IFACE_NAMELEN];
    struct sr_rt* next;
};

struct sr_arpreq {
    uint32_t ip;
    time_t sent;              Last time this ARP request was sent. You 
                                   should update this. If the ARP request was 
                                   never sent, will be 0. 
    uint32_t times_sent;        Number of times this request was sent. You 
                                   should update this. 
    struct sr_packet *packets;  List of pkts waiting on this req to finish 
    struct sr_arpreq *next;
};
ff ff ff ff ff ff 
00 a0 c9 22 b2 10 
08 06 

00 01 
08 00 
06 
04 
00 01 
00 a0 c9 22 b2 10 
ac 10 01 65 
00 00 00 00 00 00 
ac 10 01 32 
00 00 00 00 00 00
*/


void print_hex2(uint8_t * rawPacket, size_t payloadLength) {
    for(size_t i = 0; i < payloadLength; i++) {
        printf("%02x ", rawPacket[i]);
        if(i&&i%32==0) printf("\n");
    }
    printf("\n");
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);
	printf("*** -> Received packet of length %d \n",len);
	
	//print_hex2(packet, len);
	EthernetFrame * frame = new EthernetFrame(packet, len);
	switch(frame->GetType()){
		case ARP_PACKET:{
			sr_arpcache_insert(&sr->cache, frame->GetPayload()+8, flip_ip(get_int(frame->GetPayload()+14)));
			handle_arp_packet(sr, frame, interface);
			break;
		}case IP_PACKET:{
			//
			sr_arpcache_insert(&sr->cache, frame->GetPacket()+6, flip_ip(get_int(frame->GetPayload()+12)));
			handle_ip_packet(sr, frame, interface);
		}break;
		default:
			cerr << "Not a packet" << endl;
	}
	delete frame;
}/* end sr_ForwardPacket */

