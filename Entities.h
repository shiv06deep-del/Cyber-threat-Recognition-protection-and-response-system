#ifndef ENTITIES_H
#define ENTITIES_H

#include <iostream>
#include <string>

using namespace std;

class IPAddress {
public:
    string ip;
    IPAddress(string addr = "0.0.0.0") {
        ip = addr;
    }
};

class User {
public:
    string userId;
    User(string id = "GUEST") {
        userId = id;
    }
};

class Device {
public:
    string devType;
    Device(string type = "Generic") {
        devType = type;
    }
};

class LogEntry {
public:
    string timestamp;
    User user;
    Device device;
    IPAddress srcIP;
    IPAddress dstIP;
    string eventType;

    LogEntry(string ts, User u, Device dev, IPAddress src, IPAddress dst, string event) {
        timestamp = ts;
        user = u;
        device = dev;
        srcIP = src;
        dstIP = dst;
        eventType = event;
    }

    void display() {
        cout << "[" << timestamp << "] User: " << user.userId
             << " | Src: " << srcIP.ip << " (" << device.devType << ")"
             << " -> Dst: " << dstIP.ip
             << " | Event: " << eventType << endl;
    }
};

struct Node {
    LogEntry log;
    Node* next;

    Node(LogEntry entry) : log(entry) {
        next = NULL;
    }
};

#endif