#include <stdio.h>
#include <string.h>
#include "PrioritisationEngine.h"

void initPriorityQueue(PriorityQueue *pq) {
    pq->size = 0;
}

void initMaxHeap(MaxHeap *h) {
    h->size = 0;
}

int getPriority(const char classification[]) {
    if (strcmp(classification, "CRITICAL") == 0)
        return 4;

    if (strcmp(classification, "HIGH") == 0)
        return 3;

    if (strcmp(classification, "MEDIUM") == 0)
        return 2;

    return 1;
}

int higherPriority(ThreatData a, ThreatData b) {
    int priorityA = getPriority(a.classification);
    int priorityB = getPriority(b.classification);

    if (priorityA != priorityB)
        return priorityA > priorityB;

    return a.riskScore > b.riskScore;
}

void insertPriorityQueue(PriorityQueue *pq, ThreatData threat) {
    if (pq->size >= MAX)
        return;

    int i = pq->size;

    while (i > 0 && higherPriority(threat, pq->items[i - 1])) {
        pq->items[i] = pq->items[i - 1];
        i--;
    }

    pq->items[i] = threat;
    pq->size++;
}

void displayPriorityQueue(PriorityQueue *pq) {
    printf("\n========== PRIORITY QUEUE ==========\n");

    for (int i = 0; i < pq->size; i++) {
        printf("%d. %-25s Risk Score: %d | Classification: %s\n",
               i + 1,
               pq->items[i].threatName,
               pq->items[i].riskScore,
               pq->items[i].classification);
    }
}

void swapThreats(ThreatData *a, ThreatData *b) {
    ThreatData temp = *a;
    *a = *b;
    *b = temp;
}

void heapify(MaxHeap *h, int i) {
    int largest = i;
    int left = 2 * i + 1;
    int right = 2 * i + 2;

    if (left < h->size &&
        higherPriority(h->heap[left], h->heap[largest])) {
        largest = left;
    }

    if (right < h->size &&
        higherPriority(h->heap[right], h->heap[largest])) {
        largest = right;
    }

    if (largest != i) {
        swapThreats(&h->heap[i], &h->heap[largest]);
        heapify(h, largest);
    }
}

void insertMaxHeap(MaxHeap *h, ThreatData threat) {
    if (h->size >= MAX)
        return;

    int i = h->size;
    h->heap[i] = threat;
    h->size++;

    while (i > 0) {
        int parent = (i - 1) / 2;

        if (!higherPriority(h->heap[i], h->heap[parent]))
            break;

        swapThreats(&h->heap[i], &h->heap[parent]);
        i = parent;
    }
}

void transferToMaxHeap(PriorityQueue *pq, MaxHeap *h) {
    for (int i = 0; i < pq->size; i++) {
        insertMaxHeap(h, pq->items[i]);
    }
}

void displayMaxHeap(MaxHeap *h) {
    printf("\n========== MAX HEAP ==========\n");

    if (h->size == 0) {
        printf("No threats available.\n");
        return;
    }

    for (int i = 0; i < h->size; i++) {
        printf("Index %d: %-25s Risk Score: %d | Classification: %s\n",
               i,
               h->heap[i].threatName,
               h->heap[i].riskScore,
               h->heap[i].classification);
    }

    printf("\nHighest Priority Threat: %s\n",
           h->heap[0].threatName);
}

void prioritiseThreats(ThreatData threats[], int count) {
    PriorityQueue pq;
    MaxHeap h;

    initPriorityQueue(&pq);
    initMaxHeap(&h);

    if (threats == NULL || count <= 0) {
        printf("\nNo threats available for prioritisation.\n");
        return;
    }

    if (count > MAX)
        count = MAX;

    for (int i = 0; i < count; i++) {
        insertPriorityQueue(&pq, threats[i]);
    }

    displayPriorityQueue(&pq);

    transferToMaxHeap(&pq, &h);

    displayMaxHeap(&h);
}
