#include <stdio.h>
#include "alert.h"
#include "recommendation.h"

void generate_alert(const Threat *threat) {
    if (!threat) return;

    printf("\n========================================\n");
    printf("             SECURITY ALERT\n");
    printf("========================================\n");

    print_threat(threat);

    if (threat->severity == SEVERITY_CRITICAL) {
        printf("!!! IMMEDIATE MITIGATION REQUIRED !!!\n");
    } else if (threat->severity == SEVERITY_HIGH) {
        printf("High-risk event requires prompt investigation.\n");
    } else {
        printf("Event recorded for investigation.\n");
    }

    print_recommendation(threat);
    printf("========================================\n");
}

void display_prioritized_alert(const Threat *threat) {
    if (!threat) return;

    printf("[ALERT] #%d | %s | Risk %d | %s\n",
           threat->id,
           severity_to_string(threat->severity),
           threat->risk_score,
           threat_type_to_string(threat->type));
}
