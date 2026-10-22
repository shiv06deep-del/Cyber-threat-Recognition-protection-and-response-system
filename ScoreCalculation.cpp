#include <iostream>
#include <string>
#include <algorithm>
#include <cctype>

using namespace std;

class Threat {
private:
    string threatName;
    string classification;
    int likelihood;
    int severity;
    int impact;
    int frequency;
    double riskScore;

public:
    Threat(const string& name = "", int freq = 1)
        : threatName(name), classification("LOW"),
          likelihood(5), severity(5), impact(5),
          frequency(max(1, freq)), riskScore(0.0) {}

    void analyseFactors() {

        // 1. Brute Force
        if (threatName == "Brute Force") {
            severity = 8;
            likelihood = 8;
            impact = 8;
        }

        // 2. Port Scan
        else if (threatName == "Port Scan") {
            severity = 4;
            likelihood = 5;
            impact = 4;
        }

        // 3. Unauthorized Access
        else if (threatName == "Unauthorized Access") {
            severity = 9;
            likelihood = 8;
            impact = 9;
        }

        // 4. Account Compromise
        else if (threatName == "Account Compromise") {
            severity = 10;
            likelihood = 9;
            impact = 10;
        }

        // Default values for unknown threats
        else {
            severity = 5;
            likelihood = 5;
            impact = 5;
        }
    }

    void calculateScore() {
        // Equal-weight risk score
        riskScore = (likelihood + severity + impact) / 3.0;
    }

    void classifyThreat() {
        if (riskScore >= 7.0)
            classification = "HIGH";
        else if (riskScore >= 4.0)
            classification = "MEDIUM";
        else
            classification = "LOW";
    }

    void displayThreatAnalysis() const {
        cout << "Threat: " << threatName
             << " | Likelihood: " << likelihood
             << " | Severity: " << severity
             << " | Impact: " << impact
             << " | Frequency: " << frequency
             << " | Risk score: " << riskScore
             << " | Classification: " << classification << '\n';
    }

    string getThreatName() const {
        return threatName;
    }

    string getClassification() const {
        return classification;
    }

    double getRiskScore() const {
        return riskScore;
    }

    int getFrequency() const {
        return frequency;
    }
};
