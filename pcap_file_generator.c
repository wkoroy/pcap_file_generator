/*****************************
  *    Project Name:pcap_file_generator
  *    Author:V.Koroy
  *  Пт. окт. 6 15:32:33 MSK 2017
  *****************************/

#include "pcap_file_generator.h"
#include "ethernet.h"
#include "utils.h" 

// build ethernet frame
void  build_udp_frame(eth_frame_t * eth_f , network_packet_frame_t *nwp )
{
  if(!nwp || !eth_f) return;
  memcpy(eth_f->to_addr , nwp->dst_mac, sizeof(eth_f->to_addr));
  memcpy(eth_f->from_addr ,  nwp->src_mac, sizeof(eth_f->from_addr ));
  eth_f->type = ETH_TYPE_IP ;
  const int data_len = nwp->data_len + 8;

  ip_packet_t * ip_f =(ip_packet_t *) eth_f->data;
  ip_f->ver_head_len = 0x45;
  ip_f->total_len =  htons(data_len + sizeof(ip_packet_t)+sizeof(udp_packet_t));
  ip_f->fragment_id = 0;
  ip_f->flags_framgent_offset = 0;
  ip_f->ttl = 64;
  ip_f->protocol = IP_PROTOCOL_UDP;
  ip_f->cksum = ip_cksum(0, (void*)ip_f, sizeof(ip_packet_t));
  ip_f->from_addr=inet_addr( nwp->src_ip );
  ip_f->to_addr= inet_addr( nwp->dst_ip );
  
  udp_packet_t  * udp_f = (udp_packet_t  *) ip_f->data; 
  udp_f->from_port = htons( nwp->src_port );
  udp_f->to_port = htons( nwp->dst_port );  
  udp_f->len = htons(data_len);
  udp_f->cksum = ip_cksum(0, (void*)udp_f, sizeof(udp_packet_t));
  memcpy(udp_f->data, nwp->data, nwp->data_len);
  return; 
}
 
PCAPFILE * lpcap_create(char * file_path )
{
   pcap_hdr_t  p_hdr_w;
   p_hdr_w.magic_number = PCAP_MAGIC_NUM;
   p_hdr_w.version_major   = 2;
   p_hdr_w.version_minor   = 4 ;
   p_hdr_w.thiszone = 0;
   p_hdr_w.sigfigs = 0;
   p_hdr_w.snaplen = 262144;
   p_hdr_w.network = 1; 
   
   PCAPFILE *f_pcp = fopen(file_path  , "wb");
   if(f_pcp)
   {
      int res_wr = 0;
      res_wr =  fwrite(&p_hdr_w , sizeof(p_hdr_w) , 1, f_pcp );
      if(res_wr)
        return f_pcp;
     return NULL;
   } 
   return NULL; 
}


int lpcap_write_pack( PCAPFILE * f_pcp ,  pcaprec_hdr_and_data_t  *prec_frame_w)
{
   int res_wr = 0;
  
    res_wr =  fwrite(&prec_frame_w->pcp_rec_hdr , sizeof(prec_frame_w->pcp_rec_hdr) , 1, f_pcp );
    if(res_wr)
    {
           res_wr &=  fwrite(prec_frame_w->packet_data , prec_frame_w->pcp_rec_hdr.orig_len , 1, f_pcp ); 
    } 
   return res_wr;
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
           res_wr &=  fwrite(&prec_frame_w.packet_data , prec_frame_w.pcp_rec_hdr.orig_len , 1, f_pcp ); 
    } 
   return res_wr;
}

void lpcap_close_file( PCAPFILE * f_pcp )
{
    if(f_pcp)
    {
       fflush( f_pcp );
       fclose( f_pcp );
    }
}

