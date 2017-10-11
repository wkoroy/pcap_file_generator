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
           memcpy((void *)prec_frame_w.packet_data , (void *)eth_data->data , sizeof( eth_data->len ));
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
  const int  PKTS_COUNT = 212000;
  int PKTS_LEN =  540;
  int  TIME_BETWEEN_PACKETS  =  283111;/*in microseconds*/
  static ethernet_data_t  eda;
  eda.len = PKTS_LEN;

  PCAPFILE * pfl = lpcap_create("./pcaplibtestfile.pcap");
  for( i=0;i< PKTS_COUNT;i++ )
  {
   lpcap_write_data( pfl , &eda , i, 0 );
  }
  lpcap_close_file( pfl );

 return 0;
}
