#ifndef ALERT_H
#define ALERT_H

#include "threat.h"

void generate_alert(const Threat *threat);
void display_prioritized_alert(const Threat *threat);

#endif
