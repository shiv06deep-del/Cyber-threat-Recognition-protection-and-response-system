#include "LogQueue.h"

LogQueue::LogQueue() {
    front = NULL;
    rear = NULL;
}

void LogQueue::enqueue(LogEntry log) {
    Node* newNode = new Node(log);
    if (rear == NULL) {
        front = rear = newNode;
        return;
    }
    rear->next = newNode;
    rear = newNode;
}

LogEntry LogQueue::dequeue() {
    Node* temp = front;
    LogEntry data = temp->log;
    front = front->next;

    if (front == NULL) {
        rear = NULL;
    }

    delete temp;
    return data;
}

bool LogQueue::isEmpty() {
    return front == NULL;
}