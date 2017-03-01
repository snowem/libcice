#ifndef _ICE_BASE64_H_
#define _ICE_BASE64_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

unsigned char *base64_decode(const unsigned char *data,
                             size_t input_length,
                             size_t *output_length);

#ifdef __cplusplus
}
#endif

#endif // _ICE_BASE64_H_



