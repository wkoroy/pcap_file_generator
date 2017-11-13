#include "utils.h"
//thank to  http://we.easyelectronics.ru/electro-and-pc/podklyuchenie-mikrokontrollera-k-lokalnoy-seti-udp-server.html
// Рассчёт контрольной суммы для IP (и других протоколов)
uint16_t ip_cksum(uint32_t sum, uint8_t *buf, size_t len)
{
    // Рассчитываем сумму word'ов блока (big endian)
    // (блок выравнивается на word нулём)
    while(len >= 2)
    {
        sum += ((uint16_t)*buf << 8) | *(buf+1);
        buf += 2;
        len -= 2;
    }

    if(len)
        sum += (uint16_t)*buf << 8;

    // Складываем старший и младший word суммы
    // пока не получим число, влезающее в word
    while(sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    // Снова конвертируем в big endian и берём дополнение
    return ~htons((uint16_t)sum);
}
