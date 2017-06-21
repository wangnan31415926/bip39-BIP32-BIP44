#ifndef _PBKDF2_H_
#define _PBKDF2_H_

extern void pbkdf2_hmac_sha512(const uint8_t *pass, int passlen, uint8_t *salt, int saltlen, uint32_t iterations, uint8_t *key, int keylen, void (*progress_callback)(uint32_t current, uint32_t total));

#endif
