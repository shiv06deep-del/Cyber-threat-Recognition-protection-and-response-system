#include "LogLinkedList.h"

LogLinkedList::LogLinkedList() {
    head = NULL;
    tail = NULL;
}

LogLinkedList::~LogLinkedList() {
    Node* curr = head;
    while (curr != NULL) {
        Node* temp = curr->next;
        delete curr;
        curr = temp;
    }
}

void LogLinkedList::insert(LogEntry log) {
    Node* newNode = new Node(log);
    if (head == NULL) {
        head = newNode;
        tail = newNode;
    } else {
        tail->next = newNode;
        tail = newNode;
    }
}

void LogLinkedList::printAllLogs() {
    cout << "\n=== STORED LOGS (LINKED LIST) ===" << endl;
    Node* temp = head;
    while (temp != NULL) {
        temp->log.display();
        temp = temp->next;
    }
}
