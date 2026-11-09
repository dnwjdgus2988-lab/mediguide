#include <stdlib.h>
#include <stdint.h>
#include <time.h>
/* session nonce for pump command authentication from a non-CSPRNG (CWE-338) */
uint32_t new_session_nonce(void) {
    srand((unsigned)time(NULL));
    return (uint32_t)rand();
}
