
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <cstring>
#include <fstream>
#include <sstream>
#include <limits>
#include <algorithm>
#include <cctype>

using namespace std;

#include "ScoreCalculation.cpp"

extern "C" {
#include "Prioritisation_Engine.c"
}

struct SampleThreat {
    string name;
    int frequency;
};

// Convert threat names into a consistent format.
string normaliseThreatName(string name) {
    // Remove leading and trailing spaces.
    size_t start = name.find_first_not_of(" \t\r\n");
    if (start == string::npos)
        return "";

    size_t end = name.find_last_not_of(" \t\r\n");
    name = name.substr(start, end - start + 1);

    // Make the first letter of each word uppercase.
    bool newWord = true;

    for (char& ch : name) {
        if (ch == ' ') {
            newWord = true;
        } else {
            ch = static_cast<char>(
                newWord
                    ? toupper(static_cast<unsigned char>(ch))
                    : tolower(static_cast<unsigned char>(ch))
            );
            newWord = false;
        }
    }

    return name;
}

// Check whether the threat is supported by this project.
bool isSupportedThreat(const string& name) {
    return name == "Brute Force" ||
           name == "Port Scan" ||
           name == "Unauthorized Access" ||
           name == "Account Compromise";
}

// Recommend a response for each supported threat.
string recommendedResponse(const string& name) {

    if (name == "Brute Force")
        return "Rate-limit login attempts, investigate repeated failures, "
               "and enable MFA.";

    if (name == "Port Scan")
        return "Review firewall and IDS logs, investigate the source IP, "
               "and restrict unnecessary exposed ports.";

    if (name == "Unauthorized Access")
        return "Review access-control rules and audit logs, verify the "
               "attempted actions, and block unauthorised access.";

    if (name == "Account Compromise")
        return "Secure the affected account, reset credentials, revoke "
               "suspicious sessions, enable MFA, and investigate activity.";

    return "Investigate the security event.";
}

int main(int argc, char* argv[]) {

    vector<SampleThreat> threats;

    string inputFile =
        (argc > 1) ? argv[1] : "sample_threats.csv";

    ifstream file(inputFile);

    // Read threats and their frequencies from the CSV file.
    if (file) {

        string line;

        while (getline(file, line)) {

            if (line.empty() || line[0] == '#')
                continue;

            stringstream ss(line);

            string name, freqText;

            if (getline(ss, name, ',') &&
                getline(ss, freqText)) {

                name = normaliseThreatName(name);

                // Ignore an optional header.
                if (name == "Threatname" || name == "Threat")
                    continue;

                try {
                    size_t pos = 0;
                    int freq = stoi(freqText, &pos);

                    // Reject invalid frequencies.
                    if (pos != freqText.find_last_not_of(" \t\r\n") + 1 ||
                        freq <= 0) {
                        cerr << "Skipping invalid frequency: "
                             << line << '\n';
                        continue;
                    }

                    // Accept only the four required threats.
                    if (isSupportedThreat(name)) {
                        threats.push_back({name, freq});
                    } else {
                        cerr << "Skipping unsupported threat: "
                             << name << '\n';
                    }

                } catch (...) {
                    cerr << "Skipping invalid CSV row: "
                         << line << '\n';
                }
            }
        }

    } else {
        cerr << "Could not open input file: "
             << inputFile << '\n';
    }

    // Use sample data if no valid threats were found.
    if (threats.empty()) {

        cout << "Using built-in sample data.\n";

        threats = {
            {"Brute Force", 3},
            {"Port Scan", 2},
            {"Unauthorized Access", 3},
            {"Account Compromise", 1}
        };
    }

    // Initialise the priority queue.
    PriorityQueue pq;
    initQueue(&pq);

    cout << "====================================================\n";
    cout << " CYBERSECURITY THREAT RECOGNITION, PRIORITISATION\n";
    cout << "              AND RESPONSE SYSTEM\n";
    cout << "====================================================\n";

    cout << fixed << setprecision(2);

    // Section 1: Threat analysis.
    cout << "\n[1] Threat Analysis\n";
    cout << "----------------------------------------------------\n";

    for (const auto& item : threats) {

        Threat t(item.name, item.frequency);

        t.analyseFactors();
        t.calculateScore();
        t.classifyThreat();
        t.displayThreatAnalysis();

        ThreatData data{};

        strncpy(
            data.threatName,
            t.getThreatName().c_str(),
            sizeof(data.threatName) - 1
        );

        data.riskScore =
            static_cast<float>(t.getRiskScore());

        strncpy(
            data.classification,
            t.getClassification().c_str(),
            sizeof(data.classification) - 1
        );

        insert(&pq, data);
    }

    // Section 2: Sort threats using the existing C Max-Heap.
    cout << "\n[2] Threats Ranked by Priority\n";
    cout << "----------------------------------------------------\n";

    int rank = 1;

    while (pq.size > 0) {

        ThreatData t = extractMax(&pq);

        cout << rank++ << ". "
             << t.threatName
             << " | Risk Score: " << t.riskScore
             << " | Priority: " << t.classification
             << '\n';

        cout << "   Recommended Response: "
             << recommendedResponse(t.threatName)
             << "\n\n";
    }

    cout << "====================================================\n";
    cout << "Analysis completed.\n";
    cout << "Note: This program analyses predefined threat data.\n";
    cout << "It is not a live network scanner or an AI/ML detector.\n";
    cout << "====================================================\n";

    return 0;
}

