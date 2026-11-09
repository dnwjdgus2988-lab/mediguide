#include <stdint.h>
#include <string.h>
#include <openssl/md5.h>
/* firmware update integrity check with MD5 (CWE-327) */
int verify_update_image(const uint8_t *img, size_t len, const uint8_t expected[16]) {
    uint8_t digest[16]; MD5_CTX ctx;
    MD5_Init(&ctx); MD5_Update(&ctx, img, len); MD5_Final(digest, &ctx);
    return memcmp(digest, expected, 16) == 0;
}
