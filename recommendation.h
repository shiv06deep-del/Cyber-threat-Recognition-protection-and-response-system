#ifndef RECOMMENDATION_H
#define RECOMMENDATION_H

#include "threat.h"

const char *get_recommendation(ThreatType type);
void print_recommendation(const Threat *threat);

#endif
