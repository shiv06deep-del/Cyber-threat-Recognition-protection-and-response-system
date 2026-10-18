#ifndef DETECTION_H
#define DETECTION_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STR_LEN 64
#define RING    32          /* max events remembered per rule, per IP */

/* ------------------------------------------------------------------ */
/*  Basic types                                                        */
/* ------------------------------------------------------------------ */
typedef enum { EV_LOGIN_FAIL, EV_LOGIN_OK, EV_PORT_PROBE,
               EV_ACCESS_DENIED, EV_UNKNOWN, EV_COUNT } EventType;

typedef enum { TH_BRUTE_FORCE = 1, TH_PORT_SCAN, TH_UNAUTH_ACCESS,
               TH_ACCOUNT_COMPROMISE } ThreatType;

typedef struct {
    long      ts;                 /* epoch seconds */
    int       seq;                /* tie-breaker for equal timestamps */
    char      ip[STR_LEN];
    char      user[STR_LEN];      /* "-" when not applicable */
    EventType type;
    char      target[STR_LEN];    /* host / resource, "-" if none */
    int       port;               /* 0 if not applicable */
} LogEvent;

typedef struct {
    int        id;                /* ascending => binary-searchable */
    ThreatType type;
    long       ts;
    char       ip[STR_LEN];
    char       user[STR_LEN];
    char       target[STR_LEN];
    int        event_count;
    int        severity;          /* 1..10 */
    char       desc[160];
} Alert;

/* called the instant a threat is detected (observer hook) */
typedef void (*AlertCallback)(const Alert *a, void *ctx);

/* ------------------------------------------------------------------ */
/*  Hash table (separate chaining, string keys, auto-resize)           */
/* ------------------------------------------------------------------ */
typedef struct HNode { char *key; void *val; struct HNode *next; } HNode;
typedef struct { HNode **buckets; size_t cap, size; } HashTable;

HashTable *ht_create(size_t cap);
void       ht_put(HashTable *t, const char *key, void *val);   /* O(1) avg */
void      *ht_get(HashTable *t, const char *key);              /* O(1) avg */
void       ht_foreach(HashTable *t,
                      void (*fn)(const char *key, void *val, void *ctx),
                      void *ctx);
void       ht_destroy(HashTable *t, void (*free_val)(void *));

/* growable int array: indices of log events, in arrival (time) order */
typedef struct { int *a; int n, cap; } IntList;

/* ------------------------------------------------------------------ */
/*  Sliding-window ring buffer                                         */
/* ------------------------------------------------------------------ */
typedef struct { long ts[RING]; int port[RING]; int head, n; } TimeRing;

/* ------------------------------------------------------------------ */
/*  Entity profiles (stored in hash tables)                            */
/* ------------------------------------------------------------------ */
typedef struct {
    char     ip[STR_LEN];
    int      total, fails, oks, probes, denied, alerts;
    int      threat_count[5];     /* alerts per ThreatType (index 1..4) */
    long     first_seen, last_seen, last_brute;   /* last_brute = -1 if none */
    TimeRing fail_ring, probe_ring, denied_ring;
} IPProfile;

typedef struct {
    char user[STR_LEN];
    int  total, fails, oks;
    long first_seen, last_seen;
    char last_ip[STR_LEN];
} UserProfile;

/* ------------------------------------------------------------------ */
/*  Engine                                                             */
/* ------------------------------------------------------------------ */
typedef struct {
    int  brute_thresh, brute_win;     /* N failed logins in W seconds  */
    int  scan_thresh,  scan_win;      /* N distinct ports in W seconds */
    int  unauth_thresh, unauth_win;   /* N denied accesses in W seconds*/
    int  compromise_win;              /* success this soon after brute */
    long session_gap;                 /* correlation: max idle gap     */
} Config;

typedef struct {
    Config     cfg;
    LogEvent  *logs;   int nlogs,   logcap;
    Alert     *alerts; int nalerts, alertcap;
    HashTable *ip_profiles, *user_profiles;       /* entity metrics     */
    HashTable *ip_index, *user_index, *target_index; /* key -> IntList  */
    int          threat_total[5];     /* alerts per ThreatType, all IPs */
    int          late_events;         /* out-of-order live events clamped */
    AlertCallback on_alert;           /* real-time alert hook (may be NULL) */
    void        *on_alert_ctx;
} Engine;

Engine *engine_create(void);
void    engine_destroy(Engine *e);

/* ingestion + detection */
int  engine_ingest(Engine *e, LogEvent ev);       /* events in time order */
int  engine_load_file(Engine *e, const char *path); /* sorts, then ingests */

/* real-time API */
void engine_set_alert_callback(Engine *e, AlertCallback cb, void *ctx);
/* one CSV line; timestamp may be the word "now". returns 1 ok, 0 malformed, -1 blank/comment */
int  engine_ingest_line(Engine *e, const char *line);

/* searching */
const IntList *search_by_ip(Engine *e, const char *ip);          /* O(1)+k */
const IntList *search_by_user(Engine *e, const char *user);      /* O(1)+k */
const IntList *search_by_target(Engine *e, const char *target);  /* O(1)+k */
const Alert   *find_alert(Engine *e, int threat_id);             /* O(log n) */
int  search_time_range(Engine *e, long from, long to, int *lo);  /* O(log n) */

/* correlation: group events of same IP (or target) separated by <= gap */
int  engine_correlate(Engine *e, int by_target, int min_events);

/* printing */
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
