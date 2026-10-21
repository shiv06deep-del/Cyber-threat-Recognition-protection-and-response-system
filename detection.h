#ifndef DETECTION_H
#define DETECTION_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STR_LEN 64
#define RING    32          


typedef enum { EV_LOGIN_FAIL, EV_LOGIN_OK, EV_PORT_PROBE,
               EV_ACCESS_DENIED, EV_UNKNOWN, EV_COUNT } EventType;

typedef enum { TH_BRUTE_FORCE = 1, TH_PORT_SCAN, TH_UNAUTH_ACCESS,
               TH_ACCOUNT_COMPROMISE } ThreatType;

typedef struct {
    long      ts;                 
    int       seq;               
    char      ip[STR_LEN];
    char      user[STR_LEN];     
    EventType type;
    char      target[STR_LEN];   
    int       port;               
} LogEvent;

typedef struct {
    int        id;                
    ThreatType type;
    long       ts;
    char       ip[STR_LEN];
    char       user[STR_LEN];
    char       target[STR_LEN];
    int        event_count;
    int        severity;         
    char       desc[160];
} Alert;


typedef void (*AlertCallback)(const Alert *a, void *ctx);


typedef struct HNode { char *key; void *val; struct HNode *next; } HNode;
typedef struct { HNode **buckets; size_t cap, size; } HashTable;

HashTable *ht_create(size_t cap);
void       ht_put(HashTable *t, const char *key, void *val);   
void      *ht_get(HashTable *t, const char *key);              
void       ht_foreach(HashTable *t,
                      void (*fn)(const char *key, void *val, void *ctx),
                      void *ctx);
void       ht_destroy(HashTable *t, void (*free_val)(void *));

typedef struct { int *a; int n, cap; } IntList;


typedef struct { long ts[RING]; int port[RING]; int head, n; } TimeRing;


typedef struct {
    char     ip[STR_LEN];
    int      total, fails, oks, probes, denied, alerts;
    int      threat_count[5];     
    long     first_seen, last_seen, last_brute;   
    TimeRing fail_ring, probe_ring, denied_ring;
} IPProfile;

typedef struct {
    char user[STR_LEN];
    int  total, fails, oks;
    long first_seen, last_seen;
    char last_ip[STR_LEN];
} UserProfile;


typedef struct {
    int  brute_thresh, brute_win;    
    int  scan_thresh,  scan_win;      
    int  unauth_thresh, unauth_win;   
    int  compromise_win;              
    long session_gap;                 
} Config;

typedef struct {
    Config     cfg;
    LogEvent  *logs;   int nlogs,   logcap;
    Alert     *alerts; int nalerts, alertcap;
    HashTable *ip_profiles, *user_profiles;      
    HashTable *ip_index, *user_index, *target_index; 
    int          threat_total[5];     
    int          late_events;         
    AlertCallback on_alert;           
    void        *on_alert_ctx;
} Engine;

Engine *engine_create(void);
void    engine_destroy(Engine *e);


int  engine_ingest(Engine *e, LogEvent ev);       
int  engine_load_file(Engine *e, const char *path); 


void engine_set_alert_callback(Engine *e, AlertCallback cb, void *ctx);

int  engine_ingest_line(Engine *e, const char *line);


const IntList *search_by_ip(Engine *e, const char *ip);         
const IntList *search_by_user(Engine *e, const char *user);      
const IntList *search_by_target(Engine *e, const char *target);  
const Alert   *find_alert(Engine *e, int threat_id);             
int  search_time_range(Engine *e, long from, long to, int *lo);  

int  engine_correlate(Engine *e, int by_target, int min_events);


const char *event_name(EventType t);
const char *threat_name(ThreatType t);
void print_event(const LogEvent *ev);
void print_alert(const Alert *a);
void print_all_alerts(Engine *e);
int  print_ip_metrics(Engine *e, const char *ip);
int  print_user_metrics(Engine *e, const char *user);
void print_stats(Engine *e);

#ifdef __cplusplus
}
#endif
#endif
