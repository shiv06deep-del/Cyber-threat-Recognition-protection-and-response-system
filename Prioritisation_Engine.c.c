#include<stdio.h>
#include<string.h>
#define MAX 100
typedef struct{
    char threatName[50];
    float riskScore;
    char classification[10];
} threatData;

typedef struct{
    threatData heap[MAX];
    int size;
} PriorityQueue;

int getPriority(char classification[]){
    if(strcmp(classification , "HIGH"))
    return 3;
    else if(strcmp(classification , "MEDIUM"))
    return 2;
    else
    return 1;
}

int higherPriority(threatData t1 , threatData t2)
{
    int p1 = getpriority(t1.classification);
    int p2 = getpriority(t2.classification);
    if(p1<p2)
    return 1;
    if(p1<p2)
    return 0;

    if(t1.riskScore > t2.riskScore)
    return 1;
}

void swap(threatData *a , threatData *b){
    threatData temp = *a;
    *a = *b;
    *b = temp;
}

void insert(PriorityQueue *pq , threatData threat){
    if(pq->size >= MAX){
        printf("Priority Queue is Full !!\n");
        return ;
    }
    int i = pq->size;
    pq->heap[i] = threat;
    pq->size++;
    while(i > 0){
        int parent = (i-1) / 2.0;
        if(higerPriority(pq->heap[i],pq->heap[parent]))
        {
            swap(&pq->heap[i],&pq->heap[parent]);
            i=parent;
        }
        else
        break;
    }
}

threatData extractMax( PriorityQueue *pq){
    threatData maxthreat;
    if(pq->size == 0 ){
        printf("Priorirty Queue Empty ! No Threat Found !! \n");
        strcpy(maxthreat.threatName , "NONE");
        maxthreat.riskScore =0;
        strcpy(maxthreat.classification , "NONE");
        return maxthreat ;

    }
    else{
        maxthreat = pq->heap[0];
        pq->heap[0]=pq->heap[pq->size-1];
        pq->size--;
        int i=0;
        while(i){
            int l = 2*i+1;
            int r = 2*i+2;
            int highest = i;
            if((l < pq->size) && (higherPriority(pq->heap[l],pq->heap[highest])) )
            highest = l;
            if((r < pq->size) && (higherPriority(pq->heap[r],pq->heap[highest])) )
            highest = r;
            if(highest != i){
                swap(&pq->heap[i],&pq->heap[highest]);
                i=highest;
            }
            else
            break;
        }
        return maxthreat; 
    }
}

void displayQueue(PriorityQueue *pq){
    printf("\n ______Threat Priorirty Queue ______ \n");
    for(int i=0;i<pq->size ; i++){
        printf("Threat : %s | Score : %.2f | Classification : %s \n", pq->heap[i].threatName , pq->heap[i].riskScore , pq->heap[i].classification) ;
    }
}