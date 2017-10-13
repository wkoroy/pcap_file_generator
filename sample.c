#include "pcap_file_generator.h"
#include "ethernet.h"
#include "pcap_file_reader.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
/*****************************************************************************************
  *    Project Name:pcap_file_generator                                                   *
  *    Author:V.Koroy                                                                     *
  *  Пт. окт. 6 15:32:33 MSK 2017                                                         *
  * gcc -o pcap_file_generator pcap_file_generator.c sample.c                             *
  *                                                                                       * 
  *****************************************************************************************/



void print_hdr( pcap_hdr_t *ph)
{
   printf("magic_number %4x \n", ph->magic_number);
   printf(" version_major %2x \n", ph->version_major);   
   printf("version_minor %2x \n", ph->version_minor);
   printf("thiszone %d \n", ph->thiszone);
   printf("sigfigs %4x \n", ph->sigfigs);
   printf("snaplen %d \n", ph->snaplen);
   printf("network %d \n", ph->network);
}


void print_rec_hdr( pcaprec_hdr_t *ph)
{
   printf("ts_sec %i \n", (unsigned)ph->ts_sec);
   printf(" ts_usec %i \n", ph->ts_usec);   
   printf(" incl_len  %d \n", ph->incl_len);
   printf(" orig_len  %i \n", ph->orig_len);
}




int main()
{
  int i=0;
  const int  PKTS_COUNT = 20100;
  const int udp_data_sz = 1440;// udp data size
  ethernet_data_t eda;
  eda.len = udp_data_sz +(sizeof(eth_frame_t)+sizeof(ip_packet_t))+8;//34 -  headers len

  uint8_t eth_data[eda.len];
  eth_frame_t * eth_f = (eth_frame_t *) eth_data;
  network_packet_frame_t npf;
  uint8_t  m_addr[] = {0xef,0xab,0x03, 0xdc,0xee,0x11};
  memcpy(npf.dst_mac ,m_addr , sizeof(m_addr));
//change mac
  m_addr[4] = 0x44;
  m_addr[5] = 0x88;

  memcpy(npf.src_mac ,m_addr , sizeof(m_addr));
  npf.src_port = 4567;
  npf.dst_port = 4568;
  strcpy(npf.src_ip, "192.168.23.100");
  strcpy(npf.dst_ip, "192.168.22.105");
  uint8_t tdata[ udp_data_sz ];
  npf.data = tdata;
  npf.data_len = sizeof(tdata);
  build_udp_frame(eth_f , &npf ); // convert network_packet_frame_t to  eth_frame_t
  eda.data = (void *) eth_f;

  PCAPFILE * pfl = lpcap_create("./pcaplibtestfile.pcap");
  for( i=0;i< PKTS_COUNT;i++ )
  {
   lpcap_write_data( pfl , &eda , i, 0 );
  }
  lpcap_close_file( pfl );
  PCAPFILE  * pfr = lpcap_open("./pcaplibtestfile.pcap");
  pcap_hdr_t   phdr;
  if( lpcap_read_header( pfr, &phdr ))
  {
    print_hdr(&phdr);
    int rese_rec_read = 0 ;
    pcaprec_hdr_and_data_t  p_rec_data;
    do{   
       rese_rec_read = lpcap_read_frame_record( pfr , &p_rec_data);
       print_rec_hdr( &p_rec_data.pcp_rec_hdr);
    }while(rese_rec_read>0);
  } 

 return 0;
}
