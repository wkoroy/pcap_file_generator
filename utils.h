#ifndef UTILS_H
#define UTILS_H

#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

// Рассчёт контрольной суммы для IP (и других протоколов)
uint16_t ip_cksum(uint32_t sum, uint8_t *buf, size_t len);


#endif
