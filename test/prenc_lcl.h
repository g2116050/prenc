#ifndef PRENC_LCL_H
#define PRENC_LCL_H

#include <gmp.h>
#include <tepla/ec.h>

typedef struct system_param_st {
	EC_POINT P;
	EC_POINT Q;
	Element d;
} SYS_PARAM[1];

typedef struct public_key_st {
	EC_POINT sP;
	EC_POINT sQ;
} PUBLIC_KEY[1];

typedef struct private_key_st {
	mpz_t s;
	mpz_t invs;
} PRIVATE_KEY[1];

typedef struct re_key_st {
	Element rd;
} RE_KEY[1];

typedef struct cipher_text_st {
	Element ct1;
	EC_POINT ct2;
} CTXT[1];

typedef struct re_cipher_text_st {
	Element rct1;
	Element rct2;
} RE_CTXT[1];

void p_init();
void p_clear();
void pairing(Element d, EC_POINT P, EC_POINT Q);
void set_random(mpz_t x, unsigned long secbit);

void public_key_init(PUBLIC_KEY k);
void public_key_set_random(PUBLIC_KEY pubk, PRIVATE_KEY prik);
void public_key_set_from_pubk(PUBLIC_KEY pubk, PUBLIC_KEY pubk2, PRIVATE_KEY prik);
void public_key_clear(PUBLIC_KEY k);

void private_key_init(PRIVATE_KEY k);
void private_key_set_random(PRIVATE_KEY k);
void private_key_clear(PRIVATE_KEY k);

void re_key_init(RE_KEY k);
void re_key_set(RE_KEY rek, CTXT ct, PRIVATE_KEY prik, PUBLIC_KEY pubk);
void re_key_clear(RE_KEY k);

void ctxt_init(CTXT c);
void ctxt_clear(CTXT c);
void ctxt_print(CTXT c);
void re_ctxt_init(RE_CTXT c);
void re_ctxt_clear(RE_CTXT c);
void re_ctxt_print(RE_CTXT c);

/* Enc, Dec, Re_enc and Re_dec */
void enc(CTXT ct, char *msg, PUBLIC_KEY pubk, SYS_PARAM sysp);
void dec(char *msg, CTXT ct, PRIVATE_KEY prik, PUBLIC_KEY pubk, SYS_PARAM sysp);
void re_enc(RE_CTXT rct, CTXT ct, RE_KEY rek);
void re_dec(char *msg, RE_CTXT rct, PRIVATE_KEY prik);
#endif
