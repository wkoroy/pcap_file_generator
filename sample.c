#include "pcap_file_generator.h"
#include "ethernet.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
/*****************************************************************************************
  *    Project Name:pcap_file_generator                                                   *
  *    Author:V.Koroy                                                                     *
  *  Пт. окт. 6 15:32:33 MSK 2017                                                         *
  * gcc -o pcap_file_generator pcap_file_generator.c sample.c  network_packet_builder.c   *
  *                                                                                       * 
  *****************************************************************************************/


int main()
{
  int i=0;
  const int  PKTS_COUNT = 20001;
  const int udp_data_sz = 150;
  ethernet_data_t eda;
  eda.len = udp_data_sz +34;

  uint8_t eth_data[1500];
  eth_frame_t * eth_f = (eth_frame_t *) eth_data;
  network_packet_frame_t npf;
  
  uint8_t  m_addr[] = {0xef,0xab,0x03, 0xdc,0xee,0x11};
  memcpy(npf.dst_mac ,m_addr , sizeof(m_addr));
  m_addr[4] = 0x44;
  m_addr[5] = 0x88;
  memcpy(npf.src_mac ,m_addr , sizeof(m_addr));
  npf.src_port = 4567;
  npf.dst_port = 4568;
  strcpy(npf.src_ip, "192.168.23.12");
  strcpy(npf.dst_ip, "192.168.23.15");
  uint8_t tdata[ udp_data_sz ];
  npf.data = tdata;
  npf.data_len = sizeof(tdata);
  build_udp_frame(&npf , eth_f);
  eda.data = (void *) eth_f;

  PCAPFILE * pfl = lpcap_create("./pcaplibtestfile.pcap");
  for( i=0;i< PKTS_COUNT;i++ )
  {
   lpcap_write_data( pfl , &eda , i, 0 );
  }
  lpcap_close_file( pfl );

 return 0;
}
