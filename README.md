### pcap_file_generator
Эта библиотека предназначена для генерации файлов  формата PCAP .Также поддерживается генерация UDP  пакетов

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

## void  build_udp_frame(eth_frame_t * eth_f , network_packet_frame_t *nwp );
Функция генерации  пакета  ethernet данных  ethernet_data_t  на основе данных  из  network_packet_frame_t 
На вход ей поступают :
1. Указатель     на экземпляр структуры eth_frame_t  eth_f  (экземпляр  должен быть создан заранее)
2. network_packet_frame_t *nwp указатель на экземпляр структуры с нанными для Ethernet-ip-udp пакета


Пример использования 
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
