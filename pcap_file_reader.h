#ifndef PCAP_READER_H
#define PCAP_READER_H
#include "pcap_hdrs.h"

PCAPFILE * lpcap_open(char * file_path );
int   lpcap_read_header(PCAPFILE * pfl , pcap_hdr_t * phdr);
int  lpcap_read_frame_record(PCAPFILE * pfl , pcaprec_hdr_and_data_t * phdr);

#endif
