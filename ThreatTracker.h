#ifndef THREATTRACKER_H
#define THREATTRACKER_H

#include <fstream>
#include <sstream>
#include "Entities.h"

struct ThreatItem {
    string ip;
    string eventType;
    int frequency;
};

class ThreatTracker {
private:
    ThreatItem records[20];
    int totalRecords;

public:
    ThreatTracker();
    void loadFromDisk(); // <-- THIS LINE WAS MISSING OR UNSAVED
    void checkAndTrack(LogEntry log);
    void saveToFile(LogEntry log);
    void printThreatReport();
};

#endif