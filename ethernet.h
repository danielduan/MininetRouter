#ifndef _ETHERNET_
#define _ETHERNET_

#include <iostream>
#include <stdint.h>
using namespace std;

/**
EthernetFrame: CLASS
This class will parse/create an Ethernet frame object and will split/initialize its fields.
USAGE:
EthernetFrame frame1 = new EthernetFrame(raw_packet, length);
EthernetFrame frame2 = new EthernetFrame(source, destination, payload);
EthernetFrame frame3 = new EthernetFrame();
			  frame3.SetSource(source);
	          frame3.SetDest(dest);
	          frame3.SetPayload(payload);
Any of those contains a proper Ethernet frame, and it can be retrieved by
calling frameN.GetPacket();

NOTE: The layout of the ethernet frame used in this module is as defined in this wiki:
http://wiki.wireshark.org/Ethernet
dest|source|length|payload|CRC

LIMITATION: Parsing will fail with frames where the payload length is greater than 1500 (jumbo frames)
*/
class EthernetFrame{
	private:
	string rawPacket;
	size_t payloadLength;
	string destination;
	string source;
	string payload;
	uint16_t FCS;
	public:
	/**
		Default constructor
		-- Will be used to create a response that will be assembled in various steps
		e.g. create object, SetSource, SetDest, and SetPayload
	*/
	EthernetFrame();
	
	/**
		Constructor: packet, length
		-- Parse received packet
	*/
	EthernetFrame(uint8_t *, size_t);
	
	/**
		Constructor: source, dest, payload
		-- Create response in one step
	*/
	EthernetFrame(string, string, string);
	
	/**
		SetSource: set the source address this packet will contain
		-- Will recalculate CRC
	*/
	void SetSource(string);
	
	/**
		SetDest: set the destination address this packet will contain
		-- Will recalculate of CRC
	*/
	void SetDest(string);
	
	/**
		SetPayload: set the payload that will be contained in the packet
		-- Will update length, and will recalculate CRC
	*/
	void SetPayload(string);
		
	/**
		GetPacket: returns packet that's ready to be sent through the wire
		-- Will return a properly formated Ethernet frame, if any of its required fields is
		uninitialized it will pad with zeros
	*/
	string GetPacket();
	
	/**
		GetLength: returns the length field that's contained in the packet this object represents
	*/
	size_t GetLength();
	
	/**
		GetDestAddress: returns the destination address field that's contained in the packet this object represents
	*/
	string GetDestAddress();
	
	/**
		GetSrcAddress: returns the source address field that's contained in the packet this object represents
	*/
	string GetSrcAddress();
	
	/**
		GetPayload: returns the payload field that's contained in the packet this object represents
	*/
	string GetPayload();
	
	/**
		GetCR:C returns the CRC field that's contained in the packet this object represents
	*/
	uint16_t GetFCS();
	
	/**
		IsValid: returns a flag, true if the there are no errors in the packet represented by this object
	*/
	int IsValid();
};

#endif