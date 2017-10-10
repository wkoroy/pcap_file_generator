/*****************************
  *    Project Name:pcapwriter
  *    Author:V.Koroy
  *  Пт. окт. 6 15:32:33 MSK 2017
  * gcc -o pcap_file_generator pcap_file_generator.c
  *
  *****************************/
#include <stdio.h>
#include <string.h>
#include <stdint.h>

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
