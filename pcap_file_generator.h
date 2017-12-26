#ifndef PCAP_GEN_H
#define PCAP_GEN_H
#include "pcap_hdrs.h"


PCAPFILE * lpcap_create(char * file_path );
int lpcap_write_data( PCAPFILE * f_pcp ,  ethernet_data_t * eth_data, uint32_t current_seconds, uint32_t current_u_seconds);
int lpcap_write_pack( PCAPFILE * f_pcp ,  pcaprec_hdr_and_data_t  *prec_frame_w);
void lpcap_close_file( PCAPFILE * f_pcp);
uint16_t ip_cksum(uint32_t sum, uint8_t *buf, size_t len);
#endif
