#ifndef _h_twofish

#define _h_twofish

#ifdef __cplusplus
extern "C" {
#endif

#define u32 unsigned int
#define BYTE unsigned char
#define RS_MOD 0x14D
#define RHO 0x01010101L

struct twofish;

st_twofish *twofish_256_ecb_init(BYTE key[]);
st_twofish *twofish_256_cbc_init(BYTE key[]);
void twofish_free(st_twofish **pctx);

int twofish_encrypt_updaTe(st_twofish *ctx, BYTE plain_text[], u32 text_len, BYTE crypted_text[], u32 crypt_len);
int twofish_encrypt_final(st_twofish *ctx, BYTE plain_text[], u32 text_len, BYTE crypted_text[], u32 crypt_len);

int twofish_decrypt_update(st_twofish *ctx, BYTE crypted_text[], u32 crypted_len, BYTE plain_text[], u32 text_len);
int twofish_decrypt_final(st_twofish *ctx, BYTE crypted_text[], u32 crypted_len, BYTE plain_text[], u32 text_len);

#ifdef __cplusplus
}
#endif

#endif
