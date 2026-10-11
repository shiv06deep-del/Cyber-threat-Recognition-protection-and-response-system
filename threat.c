#include <stdio.h>
#include "threat.h"

const char *severity_to_string(Severity severity) {
    switch (severity) {
        case SEVERITY_LOW: return "LOW";
        case SEVERITY_MEDIUM: return "MEDIUM";
        case SEVERITY_HIGH: return "HIGH";
        case SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

const char *threat_type_to_string(ThreatType type) {
    switch (type) {
        case THREAT_FAILED_LOGIN: return "Failed Login";
        case THREAT_PORT_SCAN: return "Port Scan";
        case THREAT_UNAUTHORIZED_ACCESS: return "Unauthorized Access";
        case THREAT_MALWARE: return "Malware";
        case THREAT_SUSPICIOUS_IP: return "Suspicious IP";
        default: return "Unknown";
    }
}

void print_threat(const Threat *threat) {
    if (!threat) return;

    printf("\n--- THREAT ALERT ---\n");
    printf("ID          : %d\n", threat->id);
    printf("Timestamp   : %s\n", threat->timestamp);
    printf("Source IP   : %s\n", threat->source_ip);
    printf("User        : %s\n", threat->user);
    printf("Threat Type : %s\n", threat_type_to_string(threat->type));
    printf("Risk Score  : %d/100\n", threat->risk_score);
    printf("Severity    : %s\n", severity_to_string(threat->severity));
    printf("Description : %s\n", threat->description);
}
