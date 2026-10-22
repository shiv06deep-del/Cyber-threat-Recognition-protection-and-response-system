#ifndef THREAT_H
#define THREAT_H

#define MAX_TEXT 100
#define MAX_IP 40

typedef enum {
    SEVERITY_LOW = 1,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL
} Severity;

typedef enum {
    THREAT_UNKNOWN = 0,
    THREAT_FAILED_LOGIN,
    THREAT_PORT_SCAN,
    THREAT_UNAUTHORIZED_ACCESS,
    THREAT_MALWARE,
    THREAT_SUSPICIOUS_IP
} ThreatType;

typedef struct {
    int id;
    char timestamp[32];
    char source_ip[MAX_IP];
    char user[MAX_TEXT];
    ThreatType type;
    int risk_score;
    Severity severity;
    char description[MAX_TEXT];
} Threat;

#ifdef __cplusplus
extern "C" {
#endif

const char *severity_to_string(Severity severity);
const char *threat_type_to_string(ThreatType type);
void print_threat(const Threat *threat);

#ifdef __cplusplus
}
#endif

#endif
