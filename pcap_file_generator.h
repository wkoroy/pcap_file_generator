#ifndef PCAP_GEN_H
#define PCAP_GEN_H

typedef FILE  PCAPFILE;

typedef struct ethernet_data_s {
        uint32_t len;   
        uint8_t data[1440];
} ethernet_data_t;


typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;


typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct pcaprec_hdr_and_data_s {
       pcaprec_hdr_t pcp_rec_hdr;
       uint8_t packet_data[1440];
} pcaprec_hdr_and_data_t;

#endif
