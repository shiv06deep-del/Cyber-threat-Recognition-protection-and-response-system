#include "DataIngestionEngine.h"

LogEntry DataIngestionEngine::parseLine(string line) {
    stringstream ss(line);
    string ts, uid, dev, src, dst, event;

    getline(ss, ts, ',');
    getline(ss, uid, ',');
    getline(ss, dev, ',');
    getline(ss, src, ',');
    getline(ss, dst, ',');
    getline(ss, event, ',');

    // Clean whitespace and trailing line endings
    while (!event.empty() && (event.back() == ' ' || event.back() == '\r' || event.back() == '\n')) {
        event.pop_back();
    }
    while (!event.empty() && event.front() == ' ') {
        event.erase(0, 1);
    }

    User u(uid);
    Device d(dev);
    IPAddress sIP(src);
    IPAddress dIP(dst);

    return LogEntry(ts, u, d, sIP, dIP, event);
}

void DataIngestionEngine::receiveLogLine(string line) {
    LogEntry entry = parseLine(line);
    queue.enqueue(entry);
    cout << "[INGESTED] Log queued from: " << entry.srcIP.ip << endl;
}

void DataIngestionEngine::processAll() {
    cout << "\n--- Processing Queue (FIFO) ---" << endl;
    while (!queue.isEmpty()) {
        LogEntry log = queue.dequeue();

        list.insert(log);
       
        tracker.checkAndTrack(log);
    }
}

void DataIngestionEngine::printSummary() {
    list.printAllLogs();
  
    tracker.printThreatReport();
}