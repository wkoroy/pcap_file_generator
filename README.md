### pcap_file_generator
Эта библиотека предназначена для генерации файлов  и чтения формата PCAP .Также поддерживается генерация UDP  пакетов

Функции:
## PCAPFILE * lpcap_create(char * file_path )
Функция создает  файл и возвращает либо NULL в случае ошибки, либо  указатель  на PCAPFILE

## int lpcap_write_data( PCAPFILE * f_pcp ,  ethernet_data_t * eth_data, uint32_t current_seconds, uint32_t current_u_seconds)
Функция для заполнения файла созданного через lpcap_create, возвращает 0 при ошибке . На вход ей поступают :
 1. PCAPFILE * f_pcp  - указатель на только что созданный файл
 2. ethernet_data_t * eth_data  - кадр данных
 3. uint32_t current_seconds  - временной сдвиг в секундах относительно  предыдущего кадра
 4. uint32_t current_u_seconds - временной сдвиг в микросекундах относительно  предыдущего кадра

## void lpcap_close_file( PCAPFILE * f_pcp )
 Функция закрытия файла
На вход ей поступают :
 1. PCAPFILE * f_pcp  - указатель на открытый и записанный файл

## void  build_udp_frame(eth_frame_t * eth_f , network_packet_frame_t * nwp );
Функция генерации  пакета  ethernet-ip-udp данных  ethernet_data_t  на основе данных  из  network_packet_frame_t 
На вход ей поступают :
1. Указатель     на экземпляр структуры eth_frame_t  eth_f  (экземпляр  должен быть создан заранее)
2. network_packet_frame_t *nwp указатель на экземпляр структуры с нанными для Ethernet-ip-udp пакета

## PCAPFILE * lpcap_open(char * file_path );
Функция открытия файла. Если файл не содержит признаков PCAP  формата - возвращается 0, как и в других ошибочных ситуациях

## int   lpcap_read_header(PCAPFILE * pfl , pcap_hdr_t * phdr);
Функция  чтения заголовка файла  по дескриптору PCAPFILE * pfl  уже открытого файла в  pcap_hdr_t * phdr
phdr должен указывать на существующую область памяти. Возвращает 0 при ошибке

## int  lpcap_read_frame_record(PCAPFILE * pfl , pcaprec_hdr_and_data_t * phdr);
Функция  чтения фрейма данных  файла  по дескриптору PCAPFILE * pfl  уже открытого файла в  pcaprec_hdr_and_data_t * phdr
phdr должен указывать на существующую область памяти. Возвращает 0 при ошибке

## int  lpcap_setpos_frame_record(PCAPFILE * pfl , pcaprec_hdr_t *pcp_rec_hdr, long record_num);
Функция  перемещения указателя позиции  на номер фрейма( т.е. записи ) record_num.


Пример использования c  простой генерацией пакетов
```
  int i=0;
  const int  PKTS_COUNT = 212000;
  int PKTS_LEN =  540;
  static ethernet_data_t  eda;
  eda.len = PKTS_LEN;

  PCAPFILE * pfl = lpcap_create("./pcaplibtestfile.pcap");
  for( i=0;i< PKTS_COUNT;i++ )
  {
    /* TODO:  fill data   memcpy(eda.data , YOUR_DATA_BUF,SIZE_YOUR_DATA_BUF  );
       eda.len = SIZE_YOUR_DATA_BUF;
    */
   lpcap_write_data( pfl , &eda , i, 0 );
  }
  lpcap_close_file( pfl );

```

Пример с генерацией UDP пакетов
```
#include "pcap_file_generator.h"
#include "ethernet.h"
.......
  int i=0;
  const int  PKTS_COUNT = 2000100;
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

```

Пример чтения пакетов из файла

```
PCAPFILE  * pfr = lpcap_open("./pcaplibtestfile.pcap");
  pcap_hdr_t   phdr;
  if( lpcap_read_header( pfr, &phdr ))
  {
    int rese_rec_read = 0 ;
    pcaprec_hdr_and_data_t  p_rec_data;
    do{   
       rese_rec_read = lpcap_read_frame_record( pfr , &p_rec_data);
    }while(rese_rec_read>0);
```
