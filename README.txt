GENERAL
======================



IMPLEMENTATION
======================
Jia Dan (Daniel)'s
send_ip_packet
-Gets packet destination and searches through routing table to determine interface
-to send out of. Then using the entry found, send out out icmp packet if route exceeded
-or forwards through the packet interface. Otherwise, lookup arp table to find mac
-address to next hop or send arp request if mac address isn't found and queue packet
-to transmit later. If route is not found, send icmp for destination unreachable.

Orlando's


Kunaal's


Team's
