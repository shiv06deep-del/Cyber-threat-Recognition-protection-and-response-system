#ifndef ALERT_H
#define ALERT_H

#include "threat.h"

#ifdef __cplusplus
extern "C" {
#endif

void generate_alert(const Threat *threat);
void display_prioritized_alert(const Threat *threat);

#ifdef __cplusplus
}
#endif

#endif
