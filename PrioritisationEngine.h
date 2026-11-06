#ifndef PRIORITISATION_ENGINE_H
#define PRIORITISATION_ENGINE_H

#define MAX 100
#define THREAT_NAME_SIZE 100
#define CLASSIFICATION_SIZE 15

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char threatName[THREAT_NAME_SIZE];
    int riskScore;
    char classification[CLASSIFICATION_SIZE];
} ThreatData;

typedef struct {
    ThreatData items[MAX];
    int size;
} PriorityQueue;

typedef struct {
    ThreatData heap[MAX];
    int size;
} MaxHeap;

void initPriorityQueue(PriorityQueue *pq);
void initMaxHeap(MaxHeap *h);

int getPriority(const char classification[]);
int higherPriority(ThreatData a, ThreatData b);

void insertPriorityQueue(PriorityQueue *pq, ThreatData threat);
void displayPriorityQueue(PriorityQueue *pq);

void insertMaxHeap(MaxHeap *h, ThreatData threat);
void heapify(MaxHeap *h, int i);
void transferToMaxHeap(PriorityQueue *pq, MaxHeap *h);
void displayMaxHeap(MaxHeap *h);

void prioritiseThreats(ThreatData threats[], int count);

#ifdef __cplusplus
}
#endif

#endif