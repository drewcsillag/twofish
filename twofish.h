#ifndef _h_twofish

#define _h_twofish

#ifdef __cplusplus
extern "C" {
#endif

#define u32 unsigned int
#define BYTE unsigned char

struct twofish;

struct twofish *twofish_256_ecb_init(BYTE key[], BYTE iv[16]);
struct twofish *twofish_256_cbc_init(BYTE key[], BYTE iv[16]);

struct twofish *twofish_192_ecb_init(BYTE key[], BYTE iv[16]);
struct twofish *twofish_192_cbc_init(BYTE key[], BYTE iv[16]);

struct twofish *twofish_128_ecb_init(BYTE key[], BYTE iv[16]);
struct twofish *twofish_128_cbc_init(BYTE key[], BYTE iv[16]);

void twofish_free(struct twofish **pctx);

int twofish_encrypt_update(struct twofish *ctx, BYTE plain_text[], u32 text_len, BYTE crypted_text[], u32 crypt_len);
int twofish_encrypt_final(struct twofish *ctx, BYTE plain_text[], u32 text_len, BYTE crypted_text[], u32 crypt_len);

int twofish_decrypt_update(struct twofish *ctx, BYTE crypted_text[], u32 crypted_len, BYTE plain_text[], u32 text_len);
int twofish_decrypt_final(struct twofish *ctx, BYTE crypted_text[], u32 crypted_len, BYTE plain_text[], u32 text_len);

#ifdef __cplusplus
}
#endif

#endif
