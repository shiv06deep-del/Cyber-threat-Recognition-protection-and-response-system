#include "ThreatTracker.h"

ThreatTracker::ThreatTracker() {
    totalRecords = 0;
    loadFromDisk();
}

void ThreatTracker::loadFromDisk() {
    ifstream inFile("threats.txt");
    if (!inFile.is_open()) return;

    string line;
    while (getline(inFile, line)) {
        if (line.empty()) continue;

        size_t ipPos = line.find("IP: ");
        size_t eventPos = line.find("Event: ");
        size_t targetPos = line.find("Target: ");

        if (ipPos != string::npos && eventPos != string::npos && targetPos != string::npos) {
            string extractedIP = line.substr(ipPos + 4, eventPos - (ipPos + 4) - 3);
            string extractedEvent = line.substr(eventPos + 7, targetPos - (eventPos + 7) - 3);

            int index = -1;
            for (int i = 0; i < totalRecords; i++) {
                if (records[i].ip == extractedIP && records[i].eventType == extractedEvent) {
                    index = i;
                    break;
                }
            }

            if (index != -1) {
                records[index].frequency++;
            } else if (totalRecords < 20) {
                records[totalRecords].ip = extractedIP;
                records[totalRecords].eventType = extractedEvent;
                records[totalRecords].frequency = 1;
                totalRecords++;
            }
        }
    }
    inFile.close();
}

void ThreatTracker::checkAndTrack(LogEntry log) {
    if (log.eventType != "FAILED_LOGIN" && log.eventType != "PORT_SCAN" && log.eventType != "UNAUTHORIZED_ACCESS") {
        return;
    }

    int index = -1;
    for (int i = 0; i < totalRecords; i++) {
        if (records[i].ip == log.srcIP.ip && records[i].eventType == log.eventType) {
            index = i;
            break;
        }
    }

    if (index != -1) {
        records[index].frequency++;
    } else {
        records[totalRecords].ip = log.srcIP.ip;
        records[totalRecords].eventType = log.eventType;
        records[totalRecords].frequency = 1;
        totalRecords++;
    }

    saveToFile(log);
}

void ThreatTracker::saveToFile(LogEntry log) {
    ofstream outFile("threats.txt", ios::app);
    if (outFile.is_open()) {
        outFile << log.timestamp << " | IP: " << log.srcIP.ip 
                << " | Event: " << log.eventType 
                << " | Target: " << log.dstIP.ip << endl;
        outFile.flush();
        outFile.close();
    }
}

void ThreatTracker::printThreatReport() {
    cout << "\n=== THREAT FREQUENCY REPORT ===" << endl;
    for (int i = 0; i < totalRecords; i++) {
        cout << "Attacker IP: " << records[i].ip 
             << " | Event: " << records[i].eventType 
             << " | Frequency: " << records[i].frequency;

        if (records[i].frequency >= 2) {
            cout << " [ALERT: SUSPICIOUS ACTIVITY]";
        }
        cout << endl;
    }
    cout << "(Threat details saved to 'threats.txt')" << endl;
}