#include <stdio.h>
#include <string.h>

#define MAX 100

typedef struct {
    char threatName[50];
    float riskScore;
    char classification[10];
} ThreatData;

typedef struct {
    ThreatData heap[MAX];
    int size;
} PriorityQueue;

int getPriority(const char classification[]) {
    if (strcmp(classification, "HIGH") == 0) return 3;
    if (strcmp(classification, "MEDIUM") == 0) return 2;
    return 1;
}

int higherPriority(ThreatData a, ThreatData b) {
    int pa = getPriority(a.classification);
    int pb = getPriority(b.classification);

    if (pa != pb) return pa > pb;
    return a.riskScore > b.riskScore;
}

void swapThreats(ThreatData *a, ThreatData *b) {
    ThreatData temp = *a;
    *a = *b;
    *b = temp;
}

void initQueue(PriorityQueue *pq) {
    pq->size = 0;
}

void insert(PriorityQueue *pq, ThreatData threat) {
    if (pq->size >= MAX) {
        printf("Priority queue is full; cannot add %s.\\n", threat.threatName);
        return;
    }

    int i = pq->size++;
    pq->heap[i] = threat;

    while (i > 0) {
        int parent = (i - 1) / 2;
        if (higherPriority(pq->heap[i], pq->heap[parent])) {
            swapThreats(&pq->heap[i], &pq->heap[parent]);
            i = parent;
        } else {
            break;
        }
    }
}

ThreatData extractMax(PriorityQueue *pq) {
    ThreatData none = {"NONE", 0.0f, "NONE"};
    if (pq->size == 0) return none;

    ThreatData result = pq->heap[0];
    pq->size--;

    if (pq->size > 0) {
        pq->heap[0] = pq->heap[pq->size];
        int i = 0;

        while (1) {
            int left = 2 * i + 1;
            int right = 2 * i + 2;
            int highest = i;

            if (left < pq->size &&
                higherPriority(pq->heap[left], pq->heap[highest])) {
                highest = left;
            }
            if (right < pq->size &&
                higherPriority(pq->heap[right], pq->heap[highest])) {
                highest = right;
            }
            if (highest == i) break;

            swapThreats(&pq->heap[i], &pq->heap[highest]);
            i = highest;
        }
    }

    return result;
}

void displayQueue(const PriorityQueue *pq) {
    printf("\\n--- Threats in priority-queue heap order ---\\n");
    if (pq->size == 0) {
        printf("No threats in queue.\\n");
        return;
    }

    for (int i = 0; i < pq->size; i++) {
        printf("Threat: %-18s | Score: %5.2f | Classification: %s\\n",
               pq->heap[i].threatName,
               pq->heap[i].riskScore,
               pq->heap[i].classification);
    }
}
