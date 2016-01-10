#ifndef STRUCTPACKET_H
#define STRUCTPACKET_H

typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* Ethernet Header */
typedef struct eth_header{
    u_char dst_1;
    u_char dst_2;
    u_char dst_3;
    u_char dst_4;
    u_char dst_5;
    u_char dst_6;
    u_char src_1;
    u_char src_2;
    u_char src_3;
    u_char src_4;
    u_char src_5;
    u_char src_6;
    u_short type;
}eth_header;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    //u_int   op_pad;         // Option + Padding
}ip_header;

typedef struct icmp_header{
    u_char type;
    u_char code;
    u_short crc;
    u_short sid;
    u_short sn;

}icmp_header;

#endif // STRUCTPACKET_H
