/*****************************
  *    Project Name:pcap_file_generator
  *    Author:V.Koroy
  *  Пт. окт. 6 15:32:33 MSK 2017
  *****************************/

#include "libpcap_file_generator.h"

 
PCAPFILE * lpcap_open(char * file_path )
{
   PCAPFILE *f_pcp = fopen(file_path  , "rb");
   if(f_pcp)
   {
      uint32_t magic_number = 0;
      int res_r = 0;
      res_r =  fread(&magic_number , sizeof(magic_number) , 1, f_pcp );
      if(res_r && magic_number == PCAP_MAGIC_NUM)
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
  int res_rd  = 0;
  if(! pfl ) 
          return 0;
  
     if(feof( pfl ) )
     {     
       fclose(pfl);
       return 0;
     }
    res_rd =  fread(&phdr->pcp_rec_hdr , sizeof(phdr->pcp_rec_hdr) ,1,pfl );
    if( res_rd  && phdr->pcp_rec_hdr.incl_len )
    {
      res_rd &= fread(&phdr->packet_data,  phdr->pcp_rec_hdr.incl_len ,1,pfl );
    }
  
  return res_rd;
}


int  lpcap_setpos_frame_record(PCAPFILE * pfl , pcaprec_hdr_t *pcp_rec_hdr, long record_num)
{ 
  int res_rd  = 0;
  if(! pfl ) 
          return 0;
          
  rewind(pfl);
  fseek( pfl ,sizeof(pcap_hdr_t), SEEK_SET);
  long current_rec_num = 0;
  while(current_rec_num < record_num)
  {
    res_rd =  fread( pcp_rec_hdr , sizeof(pcp_rec_hdr[0]) ,1,pfl );
    if( res_rd  && pcp_rec_hdr->incl_len )
    {
      long fpos = ftell( pfl );
      fpos+=  pcp_rec_hdr->incl_len;
      fseek( pfl ,fpos, SEEK_SET);
    }
    else
    {
      if(res_rd<=0) break;
    }
    current_rec_num++;
  }
  return res_rd;
}

