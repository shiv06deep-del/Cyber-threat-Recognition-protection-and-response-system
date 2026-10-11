#ifndef LOGQUEUE_H
#define LOGQUEUE_H

#include "Entities.h"

class LogQueue {
private:
    Node* front;
    Node* rear;

public:
    LogQueue();
    void enqueue(LogEntry log);
    LogEntry dequeue();
    bool isEmpty();
};

#endif