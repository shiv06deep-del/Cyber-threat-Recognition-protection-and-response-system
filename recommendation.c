#include <stdio.h>
#include "recommendation.h"

const char *get_recommendation(ThreatType type) {
    switch (type) {
        case THREAT_FAILED_LOGIN:
            return "Require password reset and review failed-login history.";
        case THREAT_PORT_SCAN:
            return "Block/quarantine source IP and inspect targeted ports.";
        case THREAT_UNAUTHORIZED_ACCESS:
            return "Block access, verify user privileges, and review authentication logs.";
        case THREAT_MALWARE:
            return "Quarantine affected endpoint and start malware investigation.";
        case THREAT_SUSPICIOUS_IP:
            return "Block or quarantine IP and inspect related network activity.";
        default:
            return "Investigate the event manually and collect additional evidence.";
    }
}

void print_recommendation(const Threat *threat) {
    if (!threat) return;

    printf("Suggested Action: %s\n", get_recommendation(threat->type));
}
