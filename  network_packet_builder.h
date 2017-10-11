#ifndef  NET_PACKET_BUILDER_H
#define  NET_PACKET_BUILDER_H
#include "ethernet.h"

typedef struct network_packet_frame {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	char dst_ip[20];
	char src_ip[20];
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t *data;
	uint16_t data_len;	
} network_packet_frame_t;


void  build_udp_frame(network_packet_frame_t *nwp , eth_frame_t * eth_f );

#endif
