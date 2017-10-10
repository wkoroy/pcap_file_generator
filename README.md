### pcap_file_generator
Эта библиотека предназначена для генерации файлов  формата PCAP .

Функции:
## PCAPFILE * lpcap_create(char * file_path )
Эта функция создает  файл и возвращает либо NULL в случае ошибки, либо  указатель  на PCAPFILE

## int lpcap_write_data( PCAPFILE * f_pcp ,  ethernet_data_t * eth_data, uint32_t current_seconds, uint32_t current_u_seconds)
Эта функция для заполнения файла созданного через lpcap_create, возвращает 0 при ошибке . На вход ей поступают :
 1. PCAPFILE * f_pcp  - указатель на только что созданный файл
 2. ethernet_data_t * eth_data  - кадр данных
 3. uint32_t current_seconds  - временной сдвиг в секундах относительно  предыдущего кадра
 4. uint32_t current_u_seconds - временной сдвиг в микросекундах относительно  предыдущего кадра

## void lpcap_close_file( PCAPFILE * f_pcp )
Эта функция закрытия файла
На вход ей поступают :
 1. PCAPFILE * f_pcp  - указатель на открытый и запичсанный файл



Пример использования 
```
  int i=0;
  const int  PKTS_COUNT = 212000;
  int PKTS_LEN =  540;
  int  TIME_BETWEEN_PACKETS  =  283111;/*in microseconds*/
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
