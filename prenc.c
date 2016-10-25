#include "prenc.h"
#include <gmp.h>
#include <tepla/ec.h>
#include <stdio.h>
#include <string.h>

#define rep0(x) (((Element *)x->data)[0])
#define rep1(x) (((Element *)x->data)[1])
#define rep2(x) (((Element *)x->data)[2])
#define rep(x) (*((mpz_t *)x->data))

#define  e1(x) rep(rep0(rep0(rep0(x))))
#define  e2(x) rep(rep0(rep1(rep0(x))))
#define  e3(x) rep(rep0(rep2(rep0(x))))
#define  e4(x) rep(rep0(rep0(rep1(x))))
#define  e5(x) rep(rep0(rep1(rep1(x))))
#define  e6(x) rep(rep0(rep2(rep1(x))))
#define  e7(x) rep(rep1(rep0(rep0(x))))
#define  e8(x) rep(rep1(rep1(rep0(x))))
#define  e9(x) rep(rep1(rep2(rep0(x))))
#define e10(x) rep(rep1(rep0(rep1(x))))
#define e11(x) rep(rep1(rep1(rep1(x))))
#define e12(x) rep(rep1(rep2(rep1(x))))

EC_PAIRING p;

void
p_init()
{
	pairing_init(p, "ECBN254a");
}

void
p_clear()
{
	pairing_clear(p);
}

void
pairing(Element d, EC_POINT P, EC_POINT Q)
{
	pairing_map(d, P, Q, p);
}

void
set_random(mpz_t x, unsigned long secbit)
{
	static gmp_randstate_t state;
	static char ch = 0;

	if (!ch++) {
		gmp_randinit_default(state);
		gmp_randseed_ui(state, (unsigned long int)time(NULL));
	}
	mpz_rrandomb(x, state, secbit);
}

/*
 * PUBLIC_KEY
 */
void
public_key_init(PUBLIC_KEY k)
{
	point_init(k->P, p->g1);
	point_init(k->Q, p->g2);
	element_init(k->d, p->g3);
	point_init(k->sP, p->g1);
	point_init(k->sQ, p->g2);
}

void
public_key_set_random(PUBLIC_KEY pubk, PRIVATE_KEY prik)
{
	point_random(pubk->P);
	point_random(pubk->Q);
	pairing_map(pubk->d, pubk->P, pubk->Q, p);
	point_mul(pubk->sP, prik->s, pubk->P);
	point_mul(pubk->sQ, prik->s, pubk->Q);
}

void
public_key_set_from_pubk(PUBLIC_KEY pubk, PUBLIC_KEY pubk2, PRIVATE_KEY prik)
{
	point_set(pubk->P, pubk2->P);
	point_set(pubk->Q, pubk2->Q);
	element_set(pubk->d, pubk2->d);
	point_mul(pubk->sP, prik->s, pubk->P);
	point_mul(pubk->sQ, prik->s, pubk->Q);
}

void
public_key_clear(PUBLIC_KEY k)
{
	point_clear(k->P);
	point_clear(k->Q);
	element_clear(k->d);
	point_clear(k->sP);
	point_clear(k->sQ);
}

/*
 * PRIVATE_KEY
 */
void
private_key_init(PRIVATE_KEY k)
{
	mpz_init(k->s);
	mpz_init(k->invs);
}

void
private_key_set_random(PRIVATE_KEY k)
{
	set_random(k->s, 256);
	mpz_invert(k->invs, k->s, *curve_get_order(p->g2));
}

void
private_key_clear(PRIVATE_KEY k)
{
	mpz_clear(k->s);
	mpz_clear(k->invs);
}

/*
 * RE_ENCRYPTION_KEY
 */
void
re_key_init(RE_KEY k)
{
	element_init(k->rd, p->g3);
}

void
re_key_set(RE_KEY rek, CTXT ct, PRIVATE_KEY prik, PUBLIC_KEY pubk)
{
	EC_POINT tQ;

	point_init(tQ, p->g2);
	point_mul(tQ, prik->invs, pubk->sQ);
	pairing_map(rek->rd, ct->ct2, tQ, p);

	point_clear(tQ);
}

void
re_key_clear(RE_KEY k)
{
	element_clear(k->rd);
}

/*
 * CIPHER TEXT
 */
void
ctxt_init(CTXT c)
{
	element_init(c->ct1, p->g3);
	point_init(c->ct2, p->g1);
}

void
ctxt_clear(CTXT c)
{
	element_clear(c->ct1);
	point_clear(c->ct2);
}

void
ctxt_print(CTXT c)
{
	element_print(c->ct1);
	point_print(c->ct2);
}

void
re_ctxt_init(RE_CTXT c)
{
	element_init(c->rct1, p->g3);
	element_init(c->rct2, p->g3);
}

void
re_ctxt_clear(RE_CTXT c)
{
	element_clear(c->rct1);
	element_clear(c->rct2);
}

void
re_ctxt_print(RE_CTXT c)
{
	element_print(c->rct1);
	element_print(c->rct2);
}

/*
 * OTHER FUNCTIONS
 */
static void
hstr2e(Element d, char *hstr)
{
	char str[1024];
	snprintf(str, strlen(hstr) + 23, "%s 0 0 0 0 0 0 0 0 0 0 0", hstr);
	element_set_str(d, str);
}

static void
e2hstr(char *hstr, Element d)
{
	char str[1024];

	element_get_str(str, d);
	sscanf(hstr, "%s", str);
}

static void
m2hstr(char *hstr, char *msg)
{
	int i;
	int slen;

	slen = strlen(msg);
	for (i = 0; i < slen; i++)
		snprintf(hstr + i * 2, 3, "%02x", msg[i]);
}

static void
hstr2m(char *msg, char *hstr)
{
	int i;
	int slen;
	int cnt = 0;

	slen = strlen(hstr);
	for(i = 0; i < slen; i+=2)
		sscanf(&hstr[i], "%02x", &msg[cnt++]);
}

static void
m2e(Element d, char *msg)
{
	char str[1024];

	m2hstr(str, msg);
	hstr2e(d, str);
}

static void
e2m(char *msg, Element d)
{
	char str[1024];

	element_get_str(str, d);
	hstr2m(msg, str);
}

static void
m2mpz(mpz_t m, char *msg)
{
	int i;
	int slen;
	char buf[64];

	slen = strlen(msg);
	for (i = 0; i < slen; i++)
		snprintf(buf + i * 2, 3, "%02x", msg[i]);
	mpz_set_str(m, buf, 16);
}

static void
mpz2m(char *msg, mpz_t m)
{
	int i;
	int slen;
	int cnt = 0;
	char buf[64];
	mpz_get_str(buf, 16, m);

	slen = strlen(buf);
	for(i = 0; i < slen; i+=2)
		sscanf(&buf[i], "%02x", &msg[cnt++]);
}

static void
hstr2mpz(mpz_t m, char *hstr)
{
	mpz_set_str(m, hstr, 16);
}

static void
mpz2hstr(char *hstr, mpz_t m)
{
	mpz_get_str(hstr, 16, m);
}

/*
 * Element
 */
static void
element_scl(Element z, Element x, const mpz_t a)
{
	Element t;
	element_init(t, x->field);

	element_set_zero(t);
	mpz_set(e1(t), a);
	element_mul(z, x, t);

	element_clear(t);
}

static void
element_get_scl(mpz_t a, const Element x)
{
	mpz_set(a, e1(x));
}

static void
element_get_scl_str(char *str, const Element x)
{
	mpz_t t;
	mpz_init(t);

	element_get_scl(t, x);
	mpz2hstr(str, t);

	mpz_clear(t);
}

/*
 * ENCRYPTION, DECRYPTION, RE_ENCRYPTION, RE_DECRYPTION
 */
void
enc(CTXT ct, char *msg, PUBLIC_KEY pubk)
{
	mpz_t m;
	mpz_t r;
	mpz_init(m);
	mpz_init(r);

	hstr2mpz(m, msg);
	set_random(r, 256);

	/* ct1 */
	element_pow(ct->ct1, pubk->d, r);
	element_scl(ct->ct1, ct->ct1, m);

	/* ct2 */
	point_mul(ct->ct2, r, pubk->sP);

	mpz_clear(m);
	mpz_clear(r);
}

void
dec(char *msg, CTXT ct, PRIVATE_KEY prik, PUBLIC_KEY pubk)
{
	EC_POINT tQ;
	Element d;

	point_init(tQ, p->g2);
	element_init(d, p->g3);

	point_mul(tQ, prik->invs, pubk->Q);
	pairing_map(d, ct->ct2, tQ, p);
	element_inv(d, d);
	element_mul(d, ct->ct1, d);
	element_get_scl_str(msg, d);

	point_clear(tQ);
	element_clear(d);
}

void
re_enc(RE_CTXT rct, CTXT ct, RE_KEY rek)
{
	element_set(rct->rct1, ct->ct1);
	element_set(rct->rct2, rek->rd);
}

void
re_dec(char *msg, RE_CTXT rct, PRIVATE_KEY prik)
{
	Element d;
	element_init(d, p->g3);

	element_pow(d, rct->rct2, prik->invs);
	element_inv(d, d);
	element_mul(d, rct->rct1, d);
	element_get_scl_str(msg, d);

	element_clear(d);
}
