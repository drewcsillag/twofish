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

/* the ECB tests */
void Itest(int n)
{
    BYTE ct[16], nct[16], k1[16], k2[16], k[32];

    u32 QF[4][256];
    int i;
    u32 *KS;
    u32 K[40];
    int Kk;
    
    memset(ct, 0, 16);
    memset(nct, 0, 16);
    memset(k1, 0, 16);
    memset(k2, 0, 16);

    for (i=0; i<49; i++)
    {
	memcpy(k, k1, 16);
	memcpy(k+16, k2, 16);

	keySched(k, n, &KS, K, &Kk);
	fullKey(KS, Kk, QF);
	free(KS);
	printSubkeys(K);
	memcpy(nct, ct, 16);
    encrypt(K, QF, nct);
	printf("\nI=%d\n", i+1);
	printf("KEY="); 
	printHex(k, n/8);
	printf("\n");
	printf("PT="); printHex(ct, 16); printf("\n");
	printf("CT="); printHex(nct, 16); printf("\n");
	memcpy(k2, k1, 16);
	memcpy(k1, ct, 16);
	memcpy(ct, nct, 16);
    }
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
    u32 *S;
    u32 K[40];
    int k;
    int i;
    struct timeval tv_start, tv_end;
    double diff;
    u32 QF[4][256];
    BYTE text[16];
    BYTE key[32];

    memset(text, 0, 16);
    memset(key, 0, 32);
    keySched(key, 128, &S, K, &k);
    fullKey(S, k, QF);
    free(S);

    gettimeofday(&tv_start, NULL);
    for (i=0; i < NUMTIMES; i++)
	encrypt(K, QF, text);
    gettimeofday(&tv_end, NULL);

    diff = getTimeDiff(tv_start, tv_end);
    printf("encs/sec = %f\n", NUMTIMES/diff);
    printf("bytes/sec = %f\n", (NUMTIMES*16)/diff);
    printf("KB/sec = %f\n", NUMTIMES/(diff*64));
    printf("MB/sec = %f\n", NUMTIMES/(diff*65536));
}


int main()
{
    u32 *S;
    u32 K[40];
    int k;
    u32 QF[4][256];
    BYTE text[16];
    BYTE key[32];

    /* a few tests to make sure we didn't break anything */

    /*test encryption of null string with null key*/
    memset(text, 0, 16);
    memset(key, 0, 32);
    keySched(key, 128, &S, K, &k);
    fullKey(S, k, QF);
    free(S);
    puts("before"); printHex(text, 16); printf("\n");
    encrypt(K, QF, text);
    puts("after"); printHex(text, 16); printf("\n");

    /* 
       I=3 encryption from ECB test, again to make sure we didn't
       break anything
    */
    memcpy(key,  "\x9F\x58\x9F\x5C\xF6\x12\x2C\x32"
	         "\xB6\xBF\xEC\x2F\x2A\xE8\xC3\x5A", 16);
    memcpy(text, "\xD4\x91\xDB\x16\xE7\xB1\xC3\x9E"
	         "\x86\xCB\x08\x6B\x78\x9F\x54\x19", 16);
    keySched(key, 128, &S, K, &k);
    fullKey(S, k, QF);
    free(S);
    printf("before-->"); printHex(text, 16); printf("\n");
    encrypt(K, QF, text);
    printf("after--->"); printHex(text, 16); printf("\n");
    decrypt(K, QF, text);
    printf("after--->"); printHex(text, 16); printf("\n");

    /*Itest(128);*/

    bench();
    return 0;
}
