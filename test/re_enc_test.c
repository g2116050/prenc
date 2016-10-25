#include <stdio.h>
#include <tepla/ec.h>
#include <string.h>
#include <gmp.h>
#include "prenc_lcl.h"
#include "minunit.h"

typedef struct {
	char name[64];
	PUBLIC_KEY pubk;
	PRIVATE_KEY prik;
	RE_KEY rek;
	CTXT ct;
	RE_CTXT rct;
} USER[1];

char hmsg[64] = "abcdef0123456789abcdef0123456789";
USER a, b;

static void
user_init(USER user, char *name)
{
	strcpy(user->name, name);
	public_key_init(user->pubk);
	private_key_init(user->prik);
	re_key_init(user->rek);
	ctxt_init(user->ct);
	re_ctxt_init(user->rct);

	private_key_set_random(user->prik);
	public_key_set_random(user->pubk, user->prik);
}

static void
user_clear(USER user)
{
	public_key_clear(user->pubk);
	private_key_clear(user->prik);
	re_key_clear(user->rek);
	ctxt_clear(user->ct);
	re_ctxt_clear(user->rct);
}

int tests_run = 0;

static char
*test_enc()
{
	char rcvmsg[128];
	enc(a->ct, hmsg, a->pubk);
	dec(rcvmsg, a->ct, a->prik, a->pubk);
	printf("rcvmsg: %s\n", rcvmsg);
    mu_assert("test_enc was failed", strcmp(hmsg, rcvmsg) == 0);

	return 0;
}

static char
*test_re_enc()
{
	char rcvmsg[128];
	re_key_set(a->rek, a->ct, a->prik, b->pubk);
	re_enc(b->rct, a->ct, a->rek);
	re_dec(rcvmsg, b->rct, b->prik);
	printf("rcvmsg: %s\n", rcvmsg);
    mu_assert("test_re_enc was failed", strcmp(hmsg, rcvmsg) == 0);

	return 0;
}

static char *all_tests()
{
	p_init();
	user_init(a, "a");
	user_init(b, "b");
	public_key_set_from_pubk(b->pubk, a->pubk, b->prik);

	printf("hmsg  : %s\n", hmsg);

    mu_run_test(test_enc);
    mu_run_test(test_re_enc);

	user_clear(a);
	user_clear(b);
	p_clear();
    return 0;
}

int main(int argc, char *argv[])
{
	if (argc >= 2)
		strcpy(hmsg, argv[1]);

    char *result = all_tests();
    if (result != 0)
        printf("%s\n", result);
    else
        printf("ALL TESTS PASSED\n");
    printf("Tests run: %d\n", tests_run);
    return result != 0;
}
