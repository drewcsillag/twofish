#include <ruby.h>
#include "../../../twofish.h"

void cipher_free(void *st);

static const rb_data_type_t twofish_ctx_type = {
    "twofish_ctx",
    { 0, cipher_free, 0, },
    0, 0,
    RUBY_TYPED_FREE_IMMEDIATELY,
};

void cipher_free(void *st)
{
    struct twofish *twofish_ctx = (struct twofish *)st;
    twofish_free(&twofish_ctx);
}

#define assert_string_type(key) if (TYPE(key) != T_STRING) { rb_raise(rb_eTypeError, "type should be string"); }

#define CIPHER_ECB_INIT(self, key, len) {                                    \
    unsigned char *sKey;                                                     \
    struct twofish *ctx;                                                     \
    VALUE twofish_ctx;                                                       \
                                                                             \
    assert_string_type(key);                                                 \
    sKey = (unsigned char *)StringValuePtr(key);                             \
                                                                             \
    ctx = twofish_##len##_ecb_init(sKey, (void *)0);                         \
                                                                             \
    twofish_ctx = TypedData_Wrap_Struct(rb_cData, &twofish_ctx_type, ctx);   \
    rb_ivar_set(self, rb_intern("twofish_ctx"), twofish_ctx);                \
                                                                             \
    return Qnil;                                                             \
}

static VALUE cipher_256_ecb_init(VALUE self, VALUE key) CIPHER_ECB_INIT(self, key, 256);
static VALUE cipher_192_ecb_init(VALUE self, VALUE key) CIPHER_ECB_INIT(self, key, 192);
static VALUE cipher_128_ecb_init(VALUE self, VALUE key) CIPHER_ECB_INIT(self, key, 128);


#define CIPHER_CBC_INIT(self, key, iv, len) {                               \
    unsigned char *sKey;                                                    \
    unsigned char *sIV;                                                     \
    struct twofish *ctx;                                                    \
    VALUE twofish_ctx;                                                      \
                                                                            \
    assert_string_type(key);                                                \
    sKey = (unsigned char *)StringValuePtr(key);                            \
                                                                            \
    assert_string_type(iv);                                                 \
    sIV = (unsigned char *)StringValuePtr(iv);                              \
                                                                            \
    ctx = twofish_##len##_cbc_init(sKey, sIV);                              \
                                                                            \
    twofish_ctx = TypedData_Wrap_Struct(rb_cData, &twofish_ctx_type, ctx);  \
    rb_ivar_set(self, rb_intern("twofish_ctx"), twofish_ctx);               \
                                                                            \
    return Qnil;                                                            \
}

static VALUE cipher_256_cbc_init(VALUE self, VALUE key, VALUE iv) CIPHER_CBC_INIT(self, key, iv, 256);
static VALUE cipher_192_cbc_init(VALUE self, VALUE key, VALUE iv) CIPHER_CBC_INIT(self, key, iv, 192);
static VALUE cipher_128_cbc_init(VALUE self, VALUE key, VALUE iv) CIPHER_CBC_INIT(self, key, iv, 128);


#define CIPHER_OP(self, data, operation) {                                                    \
    unsigned char *sData, *targetData;                                            \
    unsigned int lData, lTargetData;                                              \
    int result;                                                                   \
    struct twofish *ctx;                                                          \
    VALUE twofish_ctx;                                                            \
                                                                                  \
    assert_string_type(data);                                                     \
    sData = (unsigned char *)StringValuePtr(data);                                \
    lData = RSTRING_LEN(data);                                                    \
                                                                                  \
    twofish_ctx = rb_ivar_get(self, rb_intern("twofish_ctx"));                    \
    TypedData_Get_Struct(twofish_ctx, struct twofish, &twofish_ctx_type, ctx);    \
                                                                                  \
    lTargetData = ((lData / 16) + 1) * 16;                                        \
    targetData = ALLOC_N(unsigned char, lTargetData);                             \
    result = operation(ctx, sData, lData, targetData, lTargetData);               \
                                                                                  \
    if (result < 0) {                                                             \
        rb_raise(rb_eRuntimeError, "provided length must be at least 16 bytes");  \
    }                                                                             \
                                                                                  \
    return rb_str_new(targetData, result);                                        \
}

static VALUE cipher_encrypt_update(VALUE self, VALUE data) CIPHER_OP(self, data, twofish_encrypt_update);
static VALUE cipher_encrypt_final(VALUE self, VALUE data) CIPHER_OP(self, data, twofish_encrypt_final);

static VALUE cipher_decrypt_update(VALUE self, VALUE crypted) CIPHER_OP(self, crypted, twofish_decrypt_update);
static VALUE cipher_decrypt_final(VALUE self, VALUE crypted) CIPHER_OP(self, crypted, twofish_decrypt_final);

void Init_zweifische()
{
    VALUE mZweifische,
          cCipher256ecb,
          cCipher256cbc,
          cCipher192ecb,
          cCipher192cbc,
          cCipher128ecb,
          cCipher128cbc;

    mZweifische = rb_define_module("Zweifische");

    cCipher256ecb = rb_define_class_under(mZweifische, "Cipher256ecb", rb_cObject);
    rb_define_method(cCipher256ecb, "initialize", cipher_256_ecb_init, 1);

    rb_define_method(cCipher256ecb, "encrypt_update", cipher_encrypt_update, 1);
    rb_define_method(cCipher256ecb, "encrypt_final", cipher_encrypt_final, 1);
    rb_define_method(cCipher256ecb, "decrypt_update", cipher_decrypt_update, 1);
    rb_define_method(cCipher256ecb, "decrypt_final", cipher_decrypt_final, 1);

    rb_define_alias(cCipher256ecb, "encrypt", "encrypt_final");
    rb_define_alias(cCipher256ecb, "decrypt", "decrypt_final");

    cCipher256cbc = rb_define_class_under(mZweifische, "Cipher256cbc", cCipher256ecb);
    rb_define_method(cCipher256cbc, "initialize", cipher_256_cbc_init, 2);

    cCipher192ecb = rb_define_class_under(mZweifische, "Cipher192ecb", cCipher256ecb);
    rb_define_method(cCipher192ecb, "initialize", cipher_192_ecb_init, 1);

    cCipher192cbc = rb_define_class_under(mZweifische, "Cipher192cbc", cCipher256ecb);
    rb_define_method(cCipher192cbc, "initialize", cipher_192_cbc_init, 2);

    cCipher128ecb = rb_define_class_under(mZweifische, "Cipher128ecb", cCipher256ecb);
    rb_define_method(cCipher128ecb, "initialize", cipher_128_ecb_init, 1);

    cCipher128cbc = rb_define_class_under(mZweifische, "Cipher128cbc", cCipher256ecb);
    rb_define_method(cCipher128cbc, "initialize", cipher_128_cbc_init, 2);
}
