#ifndef _LATTE_WAMR_API_H
#define _LATTE_WAMR_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int
latte_verify(uint32_t id, uint8_t *secret, uint32_t secret_size);

int
latte_attest(uint32_t id, uint8_t *ret_secret, uint32_t *ret_size);

#ifdef __cplusplus
}
#endif

#endif
