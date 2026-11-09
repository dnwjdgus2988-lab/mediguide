#include <string.h>
#include <stdint.h>
/* bolus command assembled from BLE attribute data with unbounded copy (CWE-120) */
void build_bolus_command(const char *att_data, char *out_cmd) {
    char bolus_cmd[16];
    strcpy(bolus_cmd, att_data);
    strcat(bolus_cmd, ";");
    strcpy(out_cmd, bolus_cmd);
}
