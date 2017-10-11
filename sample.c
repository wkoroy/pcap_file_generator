#include "pcap_file_generator.h"
#include "ethernet.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Пример - генерация UDP пакетов
 **/
 
int main()
{
  int i=0;
  const int  PKTS_COUNT = 20001;
  //int  TIME_BETWEEN_PACKETS  =  283111;/*in microseconds*/
  static ethernet_data_t  eda;
//-- Create ETHERNET FRAME UDP --------------------------
#if 1
  static uint8_t fdata[1700];  
  eth_frame_t * eth_f =(eth_frame_t *) fdata;
  uint8_t  m_addr[] = {0xef,0xab,0x03, 0xdc,0xee,0x11};
  memcpy(eth_f->to_addr , m_addr, sizeof(eth_f->to_addr));
  m_addr[4] = 0x44;
  m_addr[5] = 0x88;
  memcpy(eth_f->from_addr , m_addr, sizeof(eth_f->from_addr ));
  eth_f->type = ETH_TYPE_IP ;
 
  
  const int data_len = 1448+18;

  ip_packet_t * ip_f =(ip_packet_t *) eth_f->data;
  ip_f->ver_head_len = 0x45;
  ip_f->total_len = data_len + sizeof(ip_packet_t)+sizeof(udp_packet_t) ;
  ip_f->fragment_id = 0;
  ip_f->flags_framgent_offset = 0;
  ip_f->ttl = 64;
  ip_f->protocol = IP_PROTOCOL_UDP;
  ip_f->cksum = ip_cksum(0, (void*)ip_f, sizeof(ip_packet_t));
  ip_f->from_addr=inet_addr("192.168.0.1");
  ip_f->to_addr= inet_addr("192.168.0.12");
  
  udp_packet_t  * udp_f = (udp_packet_t  *) ip_f->data; 
  udp_f->from_port = htons(0x34);
  udp_f->to_port = htons( 0x33);  
  udp_f->len = htons(data_len);
  udp_f->cksum = ip_cksum(0, (void*)udp_f, sizeof(udp_packet_t));
  memset(udp_f->data, 0xab,  data_len);

  eda.data = (void *) eth_f; 
//---------------------------------------------------------------------------------
#endif

  
  eda.len = 1500;

  PCAPFILE * pfl = lpcap_create("./pcaplibtestfile.pcap");
  for( i=0;i< PKTS_COUNT;i++ )
  {
   lpcap_write_data( pfl , &eda , i, 0 );
  }
  lpcap_close_file( pfl );

 return 0;
}
