/*****************************
  *    Project Name:pcap_file_generator
  *    Author:V.Koroy
  *  Пт. окт. 6 15:32:33 MSK 2017
  *****************************/

#include "pcap_file_reader.h"
#include "ethernet.h"
 
PCAPFILE * lpcap_open(char * file_path )
{
   PCAPFILE *f_pcp = fopen(file_path  , "rb");
   if(f_pcp)
   {
      uint32_t magic_number = 0;
      int res_r = 0;
      res_r =  fread(&magic_number , sizeof(magic_number) , 1, f_pcp );
      if(res_r && magic_number ==  0xa1b2c3d4)
      {
        rewind(f_pcp);
        return f_pcp;
      }
     return NULL;
   } 
  return NULL;
}
 
int   lpcap_read_header(PCAPFILE * f_pcp , pcap_hdr_t * phdr)
{
  if(f_pcp && phdr)
   {
      long prev_pos = ftell( f_pcp ); 
      if(prev_pos !=0 ) rewind(f_pcp);
      int res_r = 0;
      res_r =  fread(phdr , sizeof(phdr[0]) , 1, f_pcp );
      if(res_r)
      {
       if(prev_pos !=0 ) fseek(f_pcp , prev_pos , SEEK_SET);
        return 1;
      } 
   } 
  return 0;
}

int  lpcap_read_frame_record(PCAPFILE * pfl , pcaprec_hdr_and_data_t * phdr)
{ 
  if(feof( pfl ))
         return 0;
  int res_rd =  fread(&phdr->pcp_rec_hdr , sizeof(phdr->pcp_rec_hdr) ,1,pfl );
  if( res_rd  && phdr->pcp_rec_hdr.incl_len )
  {
     res_rd &= fread(&phdr->packet_data,  phdr->pcp_rec_hdr.incl_len ,1,pfl );
  }
  return res_rd;
}
/*
   pcap_hdr_t  p_hdr;
   pcaprec_hdr_and_data_t  prec_frame;
   printf("\nhello   V.Koroy!\n");
   
    FILE *pcp_r = fopen("./testpcap.pcap" , "rb"); 
   //FILE *pcp_r = fopen("./test2pcp.pcap" , "rb");  
   // FILE *pcp_r = fopen("./testpcapfile1.pcap" , "rb");
   fread(&p_hdr , sizeof(p_hdr) ,1,pcp_r  );
   print_hdr(&p_hdr);

   int res_read = 0;
   int pack_counter = 0;
   do
   {
     res_read =  fread(&prec_frame.pcp_rec_hdr , sizeof(prec_frame.pcp_rec_hdr) ,1,pcp_r  );
     if( res_read ) 
     {
        pack_counter ++;
        printf("\n\n ПАкет номер %d\n",pack_counter);
        print_rec_hdr(&prec_frame.pcp_rec_hdr );
        res_read =  fread( prec_frame.packet_data , prec_frame.pcp_rec_hdr.orig_len ,1,pcp_r  );
        print_pack_data(prec_frame.packet_data , prec_frame.pcp_rec_hdr.orig_len );
     }
   
   }
   while(res_read > 0);
*/
