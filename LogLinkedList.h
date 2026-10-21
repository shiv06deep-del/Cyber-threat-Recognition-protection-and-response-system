#ifndef LOGLINKEDLIST_H
#define LOGLINKEDLIST_H

#include "Entities.h"

class LogLinkedList {
private:
    Node* head;
    Node* tail;

public:
    LogLinkedList();
    ~LogLinkedList();
    void insert(LogEntry log);
    void printAllLogs();
};

#endif
