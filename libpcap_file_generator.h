#ifndef PCAP_FILE_GENERATOR_H
#define PCAP_FILE_GENERATOR_H
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#pragma pack(1)
typedef FILE  PCAPFILE;
#define PCAP_MAGIC_NUM 0xa1b2c3d4
typedef struct ethernet_data_s {
        uint32_t len;   
        uint8_t *data;
} ethernet_data_t;

////////////////////////////////////////////// PCAP DATA TYPES
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
       uint8_t packet_data[1800];
} pcaprec_hdr_and_data_t;


//////////////////////////////////////////////////  Network types
#include <arpa/inet.h>
#pragma pack(1)

#if 0
// Перекодирование word'а
#define ___htons(a)            ((((a)>>8)&0xff)|(((a)<<8)&0xff00))
#define ___ntohs(a)            htons(a)

// Перекодирование dword'а
#define ___htonl(a)            ( (((a)>>24)&0xff) | (((a)>>8)&0xff00) |\
                                (((a)<<8)&0xff0000) | (((a)<<24)&0xff000000) )
#define ___ntohl(a)            htonl(a)

// Макрос для IP-адреса
#define ___inet_addr(a,b,c,d)    ( ((uint32_t)a) | ((uint32_t)b << 8) |\
                                ((uint32_t)c << 16) | ((uint32_t)d << 24) )
#endif

#define ETH_TYPE_ARP        htons(0x0806)
#define ETH_TYPE_IP            htons(0x0800)

// Ethernet-фрейм
typedef struct eth_frame {
    uint8_t to_addr[6]; // адрес получателя
    uint8_t from_addr[6]; // адрес отправителя
    uint16_t type; // протокол
    uint8_t  data[];
} eth_frame_t;

#define ARP_HW_TYPE_ETH        htons(0x0001)
#define ARP_PROTO_TYPE_IP    htons(0x0800)

#define ARP_TYPE_REQUEST    htons(1)
#define ARP_TYPE_RESPONSE    htons(2)

// ARP-пакет
typedef struct arp_message {
    uint16_t hw_type; // протокол канального уровня (Ethernet)
    uint16_t proto_type; // протокол сетевого уровня (IP)
    uint8_t hw_addr_len; // длина MAC-адреса =6
    uint8_t proto_addr_len; // длина IP-адреса =4
    uint16_t type; // тип сообщения (запрос/ответ)
    uint8_t mac_addr_from[6]; // MAC-адрес отправителя
    uint32_t ip_addr_from; // IP-адрес отправителя
    uint8_t mac_addr_to[6]; // MAC-адрес получателя, нули если неизвестен
    uint32_t ip_addr_to; // IP-адрес получателя
} arp_message_t;

// Коды протоколов
#define IP_PROTOCOL_ICMP    1
#define IP_PROTOCOL_TCP        6
#define IP_PROTOCOL_UDP        17

// IP-пакет
typedef struct ip_packet {
    uint8_t ver_head_len; // версия и длина заголовка =0x45
    uint8_t tos; //тип сервиса
    uint16_t total_len; //длина всего пакета
    uint16_t fragment_id; //идентификатор фрагмента
    uint16_t flags_framgent_offset; //смещение фрагмента
    uint8_t ttl; //TTL
    uint8_t protocol; //код протокола
    uint16_t cksum; //контрольная сумма заголовка
    uint32_t from_addr; //IP-адрес отправителя
    uint32_t to_addr; //IP-адрес получателя
    uint8_t data[];
} ip_packet_t;


// ICMP Echo-пакет
typedef struct icmp_echo_packet {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint16_t id;
    uint16_t seq;
    uint8_t data[];
} icmp_echo_packet_t;

// UDP-пакет
typedef struct udp_packet {
    uint16_t from_port;
    uint16_t to_port;
    uint16_t len;
    uint16_t cksum;
    uint8_t data[];
} udp_packet_t;

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

void  build_udp_frame(eth_frame_t * eth_f , network_packet_frame_t *nwp );
///////////////////////////////////////////// libpcap_file_generator functions
PCAPFILE * lpcap_open(char * file_path );
int   lpcap_read_header(PCAPFILE * pfl , pcap_hdr_t * phdr);
int  lpcap_read_frame_record(PCAPFILE * pfl , pcaprec_hdr_and_data_t * phdr);
int  lpcap_setpos_frame_record(PCAPFILE * pfl , pcaprec_hdr_t *pcp_rec_hdr, long record_num);
PCAPFILE * lpcap_create(char * file_path );
int lpcap_write_data( PCAPFILE * f_pcp ,  ethernet_data_t * eth_data, uint32_t current_seconds, uint32_t current_u_seconds);
int lpcap_write_pack( PCAPFILE * f_pcp ,  pcaprec_hdr_and_data_t  *prec_frame_w);
void lpcap_close_file( PCAPFILE * f_pcp);
uint16_t ip_cksum(uint32_t sum, uint8_t *buf, size_t len);

#endif
