#ifndef _ETHERNET_
#define _ETHERNET_

#include <iostream>
#include <stdint.h>
#include <stdio.h>
using namespace std;
enum packet_type{ BAD_PACKET, IP_PACKET, ARP_PACKET };

/**
EthernetFrame: CLASS
This class will parse/create an Ethernet frame object and will split/initialize its fields.
USAGE:
EthernetFrame frame1 = new EthernetFrame(raw_packet, length);
EthernetFrame frame2 = new EthernetFrame(source, destination, payload, payloadLength, packet_type);

NOTE: The layout of the ethernet frame used in this module isn't a full ethernet frame, but instead:
dest|source|type|payload

*/
class EthernetFrame{
	private:
	uint8_t * rawPacket;
	size_t payloadLength;
	uint8_t destination[6];
	uint8_t source[6];
	uint8_t * payload;
	enum packet_type type;
	public:
	
	/** uint8_t *s, size_t len, size_t p_eth
		Constructor: packet, length
		-- Parse received packet
	*/
	EthernetFrame(uint8_t *, size_t);
	
	~EthernetFrame();
	
	/**
		Constructor: source, dest, payload, payload length, type
		-- Create response in one step
	*/
	EthernetFrame(uint8_t *, uint8_t *, uint8_t *, size_t, enum packet_type);
		
	/**
		GetPacket: returns packet that's ready to be sent through the wire
		-- Will return a properly formated Ethernet frame, if any of its required fields is
		uninitialized it will pad with zeros
	*/
	uint8_t * GetPacket();
	
	/**
		GetDestAddress: returns the destination address field that's contained in the packet this object represents
	*/
	uint8_t * GetDestAddress();
	
	/**
		GetSrcAddress: returns the source address field that's contained in the packet this object represents
	*/
	uint8_t * GetSrcAddress();
	
	/**
		GetPayload: returns the payload field that's contained in the packet this object represents
	*/
	uint8_t * GetPayload();
	
	/**
		GetType: returns BAD_PACKET, IP_PACKET , ARP_PACKET
	*/
	enum packet_type GetType();
	
	/**
		Length: returns the length of the payload
	*/
	size_t PayloadLength();
	
	/**
		IsValid: returns a flag, true if the there are no errors in the packet represented by this object
	*/
	int IsValid();
	
	void print_hex();
};

#endif