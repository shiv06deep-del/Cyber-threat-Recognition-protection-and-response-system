#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <algorithm>

#include "detection.h"
#include "threat.h"

using namespace std;

struct ScoredThreat {
    Threat threat;
    int frequency;
    int likelihood;
    int impact;
    char classification[15];
};

class ScoreCalculation {
private:

    int getImpact(ThreatType type) {
        switch (type) {
            case THREAT_FAILED_LOGIN:
                return 8;

            case THREAT_PORT_SCAN:
                return 5;

            case THREAT_UNAUTHORIZED_ACCESS:
                return 9;

            case THREAT_MALWARE:
                return 10;

            case THREAT_SUSPICIOUS_IP:
                return 7;

            default:
                return 5;
        }
    }

    ThreatType mapThreatType(ThreatType type) {
        return type;
    }

    ThreatType convertDetectionType(ThreatType type) {
        return THREAT_UNKNOWN;
    }

    void assignFactors(ScoredThreat &result, const Alert &alert) {
        result.likelihood = min(10, 4 + result.frequency * 2);

        result.impact = getImpact(result.threat.type);

        int severityFactor = max(1, min(10, alert.severity));

        int frequencyFactor = min(10, result.frequency * 2);

        result.threat.risk_score =
            ((result.likelihood + severityFactor +
              result.impact + frequencyFactor) * 100) / 40;

        if (result.threat.risk_score >= 85) {
            result.threat.severity = SEVERITY_CRITICAL;
            strcpy(result.classification, "CRITICAL");
        }
        else if (result.threat.risk_score >= 70) {
            result.threat.severity = SEVERITY_HIGH;
            strcpy(result.classification, "HIGH");
        }
        else if (result.threat.risk_score >= 40) {
            result.threat.severity = SEVERITY_MEDIUM;
            strcpy(result.classification, "MEDIUM");
        }
        else {
            result.threat.severity = SEVERITY_LOW;
            strcpy(result.classification, "LOW");
        }
    }

public:

    int calculateScores(Engine *engine, ScoredThreat results[], int capacity) {

        if (engine == nullptr || results == nullptr || capacity <= 0) {
            return 0;
        }

        vector<ScoredThreat> threats;

        for (int i = 0; i < engine->nalerts; i++) {

            Alert alert = engine->alerts[i];

            ThreatType mappedType;

            switch (alert.type) {
                case TH_BRUTE_FORCE:
                    mappedType = THREAT_FAILED_LOGIN;
                    break;

                case TH_PORT_SCAN:
                    mappedType = THREAT_PORT_SCAN;
                    break;

                case TH_UNAUTH_ACCESS:
                    mappedType = THREAT_UNAUTHORIZED_ACCESS;
                    break;

                case TH_ACCOUNT_COMPROMISE:
                    mappedType = THREAT_UNAUTHORIZED_ACCESS;
                    break;

                default:
                    continue;
            }

            int index = -1;

            for (int j = 0; j < (int)threats.size(); j++) {
                if (threats[j].threat.type == mappedType &&
                    strcmp(threats[j].threat.source_ip, alert.ip) == 0) {
                    index = j;
                    break;
                }
            }

            if (index == -1) {

                if ((int)threats.size() >= capacity) {
                    continue;
                }

                ScoredThreat newThreat{};

                newThreat.threat.id = (int)threats.size() + 1;
                newThreat.threat.type = mappedType;
                newThreat.frequency = 1;

                strcpy(newThreat.threat.source_ip, alert.ip);
                strcpy(newThreat.threat.user, alert.user);

                snprintf(
                    newThreat.threat.timestamp,
                    sizeof(newThreat.threat.timestamp),
                    "%ld",
                    alert.ts
                );

                snprintf(
                    newThreat.threat.description,
                    sizeof(newThreat.threat.description),
                    "%s",
                    alert.desc
                );

                threats.push_back(newThreat);
            }
            else {
                threats[index].frequency++;

                if (alert.severity > 0) {
                    snprintf(
                        threats[index].threat.description,
                        sizeof(threats[index].threat.description),
                        "%s",
                        alert.desc
                    );
                }
            }
        }

        for (int i = 0; i < (int)threats.size(); i++) {

            const Alert *latestAlert = nullptr;

            for (int j = engine->nalerts - 1; j >= 0; j--) {
                if (strcmp(engine->alerts[j].ip,
                           threats[i].threat.source_ip) == 0) {
                    latestAlert = &engine->alerts[j];
                    break;
                }
            }

            if (latestAlert != nullptr) {
                assignFactors(threats[i], *latestAlert);
            }

            results[i] = threats[i];
        }

        return (int)threats.size();
    }

    void displayResults(ScoredThreat results[], int count) {

        cout << "\n========== THREAT SCORE ANALYSIS ==========\n";

        for (int i = 0; i < count; i++) {

            cout << "\nThreat ID       : "
                 << results[i].threat.id;

            cout << "\nThreat Type     : "
                 << threat_type_to_string(results[i].threat.type);

            cout << "\nSource IP       : "
                 << results[i].threat.source_ip;

            cout << "\nFrequency       : "
                 << results[i].frequency;

            cout << "\nLikelihood      : "
                 << results[i].likelihood << "/10";

            cout << "\nImpact          : "
                 << results[i].impact << "/10";

            cout << "\nRisk Score      : "
                 << results[i].threat.risk_score << "/100";

            cout << "\nClassification  : "
                 << results[i].classification;

            cout << "\nSeverity        : "
                 << severity_to_string(results[i].threat.severity);

            cout << "\n-------------------------------------------\n";
        }
    }
};
