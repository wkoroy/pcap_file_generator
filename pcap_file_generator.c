/*****************************
  *    Project Name:pcap_file_generator
  *    Author:V.Koroy
  *  Пт. окт. 6 15:32:33 MSK 2017
  * gcc -o pcap_file_generator pcap_file_generator.c
  *
  *****************************/
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "pcap_file_generator.h"
#include "ethernet.h"


// Рассчёт контрольной суммы для IP (и других протоколов)
uint16_t ip_cksum(uint32_t sum, uint8_t *buf, size_t len)
{
    // Рассчитываем сумму word'ов блока (big endian)
    // (блок выравнивается на word нулём)
    while(len >= 2)
    {
        sum += ((uint16_t)*buf << 8) | *(buf+1);
        buf += 2;
        len -= 2;
    }

    if(len)
        sum += (uint16_t)*buf << 8;

    // Складываем старший и младший word суммы
    // пока не получим число, влезающее в word
    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    // Снова конвертируем в big endian и берём дополнение
    return ~htons((uint16_t)sum);
}
 
PCAPFILE * lpcap_create(char * file_path )
{
   pcap_hdr_t  p_hdr_w;
   p_hdr_w.magic_number = 0xa1b2c3d4;
   p_hdr_w.version_major   = 2;
   p_hdr_w.version_minor   = 4 ;
   p_hdr_w.thiszone = 0;
   p_hdr_w.sigfigs = 0;
   p_hdr_w.snaplen = 262144;
   p_hdr_w.network = 1; 
   pcaprec_hdr_and_data_t  prec_frame_w;


   PCAPFILE *f_pcp = fopen(file_path  , "wb");
   if(f_pcp)
   {
      int res_wr = 0;
      res_wr =  fwrite(&p_hdr_w , sizeof(p_hdr_w) , 1, f_pcp );
      return f_pcp;
   } 
   return NULL; 
}

int lpcap_write_data( PCAPFILE * f_pcp ,  ethernet_data_t * eth_data, uint32_t current_seconds, uint32_t current_u_seconds)
{
   int res_wr = 0;
   pcaprec_hdr_and_data_t  prec_frame_w;
   prec_frame_w.pcp_rec_hdr.ts_sec = current_seconds;
   prec_frame_w.pcp_rec_hdr.ts_usec = current_u_seconds;


   prec_frame_w.pcp_rec_hdr.orig_len =  eth_data->len;
   prec_frame_w.pcp_rec_hdr.incl_len =eth_data->len;

    res_wr =  fwrite(&prec_frame_w.pcp_rec_hdr , sizeof(prec_frame_w.pcp_rec_hdr) , 1, f_pcp );
    if(res_wr)
    {
           memcpy((void *)prec_frame_w.packet_data , (void *)eth_data->data ,  ( eth_data->len ));
           res_wr |=  fwrite(&prec_frame_w.packet_data , prec_frame_w.pcp_rec_hdr.orig_len , 1, f_pcp ); 
    } 
   return res_wr;
}

void lpcap_close_file( PCAPFILE * f_pcp )
{
    if(f_pcp)
    {
       fclose( f_pcp );
    }
}

int main()
{
  int i=0;
  const int  PKTS_COUNT = 2;
  int PKTS_LEN =  540;
  uint8_t e_data[PKTS_LEN];
  int  TIME_BETWEEN_PACKETS  =  283111;/*in microseconds*/
  static ethernet_data_t  eda;
//-- Create ETHERNET FRAME --------------------------
   uint8_t fdata[1700];  
  eth_frame_t * eth_f =(eth_frame_t *) fdata;
  uint8_t  m_addr[] = {0xef,0xab,0x03, 0xdc,0xee,0x11};
  memcpy(eth_f->to_addr , m_addr, sizeof(eth_f->to_addr));
  m_addr[4] = 0x44;
  m_addr[5] = 0x88;
  memcpy(eth_f->from_addr , m_addr, sizeof(eth_f->from_addr ));
  eth_f->type = ETH_TYPE_IP ;
 #if 1
  
  const int data_len = 1448+18;

  ip_packet_t * ip_f =(ip_packet_t *) eth_f->data;
  ip_f->ver_head_len = 0x45;
  ip_f->total_len = data_len + sizeof(ip_packet_t)+sizeof(udp_packet_t) +58;
  ip_f->fragment_id = 0;
  ip_f->flags_framgent_offset = 0;
  ip_f->ttl = 64;
  ip_f->protocol = IP_PROTOCOL_UDP;
  ip_f->cksum = ip_cksum(0, (void*)ip_f, sizeof(ip_packet_t));
  ip_f->from_addr=inet_addr("192.168.0.1");//___inet_addr(0x01,0x00,0xa8,0xc0); //inet_addr(0xc0,0xa8,0x00, 0x01);
  ip_f->to_addr= inet_addr("192.168.0.12");//___inet_addr(0x02,0x00,0xa8,0xc0);
  
  udp_packet_t  * udp_f = (udp_packet_t  *) ip_f->data; 
  udp_f->from_port = htons(0x34);
  udp_f->to_port = htons( 0x33);  
  udp_f->len = htons(data_len);
  udp_f->cksum = ip_cksum(0, (void*)udp_f, sizeof(udp_packet_t));
  memset(udp_f->data, 0xab,  data_len);
//--------------------------------------
#endif

  eda.data = eth_f; 
  eda.len = 1500;

  PCAPFILE * pfl = lpcap_create("./pcaplibtestfile.pcap");
  for( i=0;i< PKTS_COUNT;i++ )
  {
   
   lpcap_write_data( pfl , &eda , i, 0 );
  }
  lpcap_close_file( pfl );

 return 0;
}
