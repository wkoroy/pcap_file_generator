#ifndef ETHERNET_H
#define ETHERNET_H

#include <arpa/inet.h>
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
    uint8_t *data;
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
    uint8_t *data;
} ip_packet_t;


// ICMP Echo-пакет
typedef struct icmp_echo_packet {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint16_t id;
    uint16_t seq;
    uint8_t *data;
} icmp_echo_packet_t;

// UDP-пакет
typedef struct udp_packet {
    uint16_t from_port;
    uint16_t to_port;
    uint16_t len;
    uint16_t cksum;
    uint8_t *data;
} udp_packet_t;

#endif
