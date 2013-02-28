#ifndef _ETHERNET_
#define _ETHERNET_

/** NOTE: The layout of the ethernet frame used in this module is posted in the following blog:
https://communities.netapp.com/blogs/ethernetstorageguy/2009/09/12/anatomy-of-an-ethernet-frame
preamble|dest|source|length|payload|CRC
*/


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
Any of those methods will create a proper Ethernet frame, and it can be retrieved by
calling frameN.GetPacket();
*/
class EthernetFrame{
	private:
	uint8_t * raw_packet;
	unsigned int length;
	string preamble;
	string destination;
	string source;
	string payload;
	strinc CRC;
	void calculateCRC();
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
	EthernetFrame(uint8_t *, int);
	
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
	uint8_t * GetPacket();
	
	/**
		GetLength: returns the length field that's contained in the packet this object represents
	*/
	unsigned int GetLength();
	
	/**
		GetPreamble: returns the preamble field that's contained in the packet this object represents
	*/
	string GetPreamble();
	
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
	string GetCRC();
}

#endif