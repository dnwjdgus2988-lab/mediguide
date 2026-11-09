#include <stdio.h>
/* event log where the format string comes from the BLE peer (CWE-134) */
void log_pump_event(const char *msg_from_peer) {
    printf(msg_from_peer);
}
