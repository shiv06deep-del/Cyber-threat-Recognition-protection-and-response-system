#include <iostream>
#include <string>
#include "DataIngestionEngine.h"

using namespace std;

int main() {
    DataIngestionEngine engine;
    int choice;

    cout << "===========================================" << endl;
    cout << "   CYBERSECURITY LOG INGESTION ENGINE      " << endl;
    cout << "===========================================" << endl;
    cout << "1. Run with Sample Attack Logs" << endl;
    cout << "2. Enter Custom Logs Manually" << endl;
    cout << "Select Option (1 or 2): ";
    cin >> choice;
    cin.ignore();

    if (choice == 2) {
        int numLogs;
        cout << "\nEnter number of logs you want to enter: ";
        cin >> numLogs;
        cin.ignore();

        cout << "\n--- Enter Logs in CSV Format ---" << endl;
        cout << "Format: Timestamp,UserID,DeviceType,SourceIP,DestIP,EventType" << endl;
        cout << "Threat Events: FAILED_LOGIN, PORT_SCAN, UNAUTHORIZED_ACCESS" << endl;

        for (int i = 0; i < numLogs; i++) {
            string customLog;
            cout << "Enter Log #" << (i + 1) << ": ";
            getline(cin, customLog);
            engine.receiveLogLine(customLog);
        }
    } else {
        string sampleLogs[6] = {
            "2026-10-04 10:00:01,ATTACKER,Client,192.168.1.50,192.168.1.1,FAILED_LOGIN",
            "2026-10-04 10:00:03,ATTACKER,Client,192.168.1.50,192.168.1.1,FAILED_LOGIN",
            "2026-10-04 10:00:05,SCANNER,Client,10.0.0.99,192.168.1.1,PORT_SCAN",
            "2026-10-04 10:00:07,SCANNER,Client,10.0.0.99,192.168.1.2,PORT_SCAN",
            "2026-10-04 10:00:10,USR101,Client,192.168.1.10,192.168.1.1,LOGIN_SUCCESS",
            "2026-10-04 10:00:12,ATTACKER,Client,192.168.1.50,192.168.1.1,FAILED_LOGIN"
        };

        cout << "\n--- Processing Default Sample Logs ---" << endl;
        for (int i = 0; i < 6; i++) {
            engine.receiveLogLine(sampleLogs[i]);
        }
    }

    engine.processAll();
    engine.printSummary();

    return 0;
}