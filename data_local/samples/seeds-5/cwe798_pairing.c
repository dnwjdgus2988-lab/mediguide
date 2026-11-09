#include <string.h>
#include <stdint.h>
/* BLE pairing secret hard-coded in firmware (CWE-798) */
static const char PAIRING_SECRET[] = "pump-2024-secret";
int ble_verify_pairing(const char *presented) {
    return strcmp(presented, PAIRING_SECRET) == 0;
}
