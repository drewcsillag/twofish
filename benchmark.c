#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "twofish.h"


/***********************************************************************
  TESTING FUNCTIONS AND STUFF STARTS HERE
***********************************************************************/
void printHex(BYTE b[], int lim)
{
    int i;
    for (i=0; i<lim;i++) 
	printf("%02X", (u32)b[i]);
}

void printRound(int round, u32 R0, u32 R1, u32 R2, u32 R3, u32 K1, u32 K2)
{
    printf("round[%d] ['0x%08XL', '0x%08XL', '0x%08XL', '0x%08XL']\n", 
	   round, R0, R1, R2, R3);

}

void printSubkeys(u32 K[40])
{
    int i;
    printf("round subkeys\n");
    for (i=0;i<40;i+=2)
	printf("%08X %08X\n", K[i], K[i+1]);
}

#include <sys/time.h>
#include <unistd.h>
#include <time.h>

double getTimeDiff(struct timeval t1, struct timeval t2)
{
    long us1;
    long us2;
    us1 = t2.tv_sec - t1.tv_sec;
    us2 = t2.tv_usec - t1.tv_usec;
    if (us2 < 0)
    {
	us1--;
	us2 += 1000000;
    }
    return us1 + (us2 / 1000000.0);
}

/* a million encryptions should give us a good feel for how we're doing */
#define NUMTIMES 1000000
void bench()
{
    int i;
    struct timeval tv_start, tv_end;
    double diff;
    BYTE text[16];
    BYTE key[32];
    struct twofish *twofish_ctx;

    memset(text, 0, 16);
    memset(key, 0, 32);
    twofish_ctx = twofish_256_ecb_init(key, (void *) 0);

    gettimeofday(&tv_start, NULL);
    for (i=0; i < NUMTIMES; i++)
	    twofish_encrypt_final(twofish_ctx, text, 16, text, 16);
    gettimeofday(&tv_end, NULL);

    twofish_free(&twofish_ctx);

    diff = getTimeDiff(tv_start, tv_end);
    printf("encs/sec = %f\n", NUMTIMES/diff);
    printf("bytes/sec = %f\n", (NUMTIMES*16)/diff);
    printf("KB/sec = %f\n", NUMTIMES/(diff*64));
    printf("MB/sec = %f\n", NUMTIMES/(diff*65536));
}


int main()
{
    BYTE text[16];
    BYTE crypt[16];
    BYTE iv[16] = "AAAABBBBCCCCDDDD";
    BYTE key[32];

    /* 
       I=3 encryption from ECB test, again to make sure we didn't
       break anything
    */
    memset(key, 0, 32);
    memset(crypt, 0, 16);

    memcpy(key,  "\x9F\x58\x9F\x5C\xF6\x12\x2C\x32"
	         "\xB6\xBF\xEC\x2F\x2A\xE8\xC3\x5A", 16);
    memcpy(text, "\xD4\x91\xDB\x16\xE7\xB1\xC3\x9E"
	         "\x86\xCB\x08\x6B\x78\x9F\x54\x19", 16);

    struct twofish *twofish_ecb_ctx = twofish_256_ecb_init(key, (void *) 0);
    struct twofish *twofish_cbc_ctx = twofish_256_cbc_init(key, iv);

    printf("before-->     "); printHex(text, 16); printf("\n");
    twofish_encrypt_final(twofish_ecb_ctx, text, 16, crypt, 16);
    printf("after ecb --->"); printHex(crypt, 16); printf("\n");
    twofish_decrypt_final(twofish_ecb_ctx, crypt, 16, text, 16);
    printf("decrypted --->"); printHex(text, 16); printf("\n");
    twofish_encrypt_final(twofish_cbc_ctx, text, 16, crypt, 16);
    printf("after cbc --->"); printHex(crypt, 16); printf("\n");
    twofish_decrypt_final(twofish_cbc_ctx, crypt, 16, text, 16);
    printf("decrypted --->"); printHex(text, 16); printf("\n");

    /*Itest(128);*/
    twofish_free(&twofish_ecb_ctx);
    twofish_free(&twofish_cbc_ctx);

    bench();
    return 0;
}
