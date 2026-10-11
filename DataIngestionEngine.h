#ifndef DATAINGESTIONENGINE_H
#define DATAINGESTIONENGINE_H

#include <sstream>
#include "LogQueue.h"
#include "LogLinkedList.h"

#include "ThreatTracker.h"

class DataIngestionEngine {
private:
    LogQueue queue;
    LogLinkedList list;
   
    ThreatTracker tracker;

public:
    LogEntry parseLine(string line);
    void receiveLogLine(string line);
    void processAll();
    void printSummary();
};

#endif