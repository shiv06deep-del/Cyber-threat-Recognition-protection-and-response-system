#ifndef RECOMMENDATION_H
#define RECOMMENDATION_H

#include "threat.h"

#ifdef __cplusplus
extern "C" {
#endif

const char *get_recommendation(ThreatType type);
void print_recommendation(const Threat *threat);

#ifdef __cplusplus
}
#endif

#endif
