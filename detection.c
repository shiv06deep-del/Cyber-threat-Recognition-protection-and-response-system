#include "detection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

static void scopy(char *dst, const char *src) { snprintf(dst, STR_LEN, "%s", src); }
static char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1; char *p = (char *)malloc(n); memcpy(p, s, n); return p;
}


static unsigned long djb2(const char *s) {
    unsigned long h = 5381; int c;
    while ((c = (unsigned char)*s++)) h = ((h << 5) + h) + c;
    return h;
}

HashTable *ht_create(size_t cap) {
    HashTable *t = (HashTable *)malloc(sizeof *t);
    t->cap = cap ? cap : 16;
    t->size = 0;
    t->buckets = (HNode **)calloc(t->cap, sizeof(HNode *));
    return t;
}

static void ht_resize(HashTable *t) {
    size_t ncap = t->cap * 2;
    HNode **nb = (HNode **)calloc(ncap, sizeof(HNode *));
    for (size_t i = 0; i < t->cap; i++) {
        HNode *n = t->buckets[i];
        while (n) {
            HNode *next = n->next;
            size_t j = djb2(n->key) % ncap;
            n->next = nb[j]; nb[j] = n;
            n = next;
        }
    }
    free(t->buckets);
    t->buckets = nb; t->cap = ncap;
}

void ht_put(HashTable *t, const char *key, void *val) {
    size_t i = djb2(key) % t->cap;
    for (HNode *n = t->buckets[i]; n; n = n->next)
        if (!strcmp(n->key, key)) { n->val = val; return; }
    HNode *n = (HNode *)malloc(sizeof *n);
    n->key = xstrdup(key); n->val = val;
    n->next = t->buckets[i]; t->buckets[i] = n;
    if (++t->size > t->cap * 3 / 4) ht_resize(t);
}

void *ht_get(HashTable *t, const char *key) {
    for (HNode *n = t->buckets[djb2(key) % t->cap]; n; n = n->next)
        if (!strcmp(n->key, key)) return n->val;
    return NULL;
}

void ht_foreach(HashTable *t, void (*fn)(const char *, void *, void *), void *ctx) {
    for (size_t i = 0; i < t->cap; i++)
        for (HNode *n = t->buckets[i]; n; n = n->next) fn(n->key, n->val, ctx);
}

void ht_destroy(HashTable *t, void (*free_val)(void *)) {
    for (size_t i = 0; i < t->cap; i++) {
        HNode *n = t->buckets[i];
        while (n) {
            HNode *next = n->next;
            if (free_val) free_val(n->val);
            free(n->key); free(n);
            n = next;
        }
    }
    free(t->buckets); free(t);
}

/* ---- IntList ---- */
static void il_push(IntList *l, int v) {
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 4;
        l->a = (int *)realloc(l->a, l->cap * sizeof(int));
    }
    l->a[l->n++] = v;
}
static void il_free(void *p) { IntList *l = (IntList *)p; free(l->a); free(l); }


static void ring_push(TimeRing *r, long ts, int port) {
    r->ts[r->head] = ts; r->port[r->head] = port;
    r->head = (r->head + 1) % RING;
    if (r->n < RING) r->n++;
}
static void ring_clear(TimeRing *r) { r->n = 0; r->head = 0; }


static int ring_at(const TimeRing *r, int i) { return (r->head - 1 - i + 2 * RING) % RING; }


static int ring_count(const TimeRing *r, long now, int win) {
    int c = 0;
    for (int i = 0; i < r->n; i++) {
        if (now - r->ts[ring_at(r, i)] > win) break;
        c++;
    }
    return c;
}

static int ring_distinct_ports(const TimeRing *r, long now, int win) {
    int seen[RING], d = 0;
    for (int i = 0; i < r->n; i++) {
        int k = ring_at(r, i);
        if (now - r->ts[k] > win) break;
        int dup = 0;
        for (int j = 0; j < d; j++) if (seen[j] == r->port[k]) { dup = 1; break; }
        if (!dup) seen[d++] = r->port[k];
    }
    return d;
}


Engine *engine_create(void) {
    Engine *e = (Engine *)calloc(1, sizeof *e);
    e->cfg.brute_thresh   = 5;   e->cfg.brute_win    = 60;
    e->cfg.scan_thresh    = 10;  e->cfg.scan_win     = 30;
    e->cfg.unauth_thresh  = 3;   e->cfg.unauth_win   = 120;
    e->cfg.compromise_win = 300; e->cfg.session_gap  = 120;
    e->ip_profiles   = ht_create(64);
    e->user_profiles = ht_create(64);
    e->ip_index      = ht_create(64);
    e->user_index    = ht_create(64);
    e->target_index  = ht_create(64);
    return e;
}

void engine_destroy(Engine *e) {
    ht_destroy(e->ip_profiles, free);
    ht_destroy(e->user_profiles, free);
    ht_destroy(e->ip_index, il_free);
    ht_destroy(e->user_index, il_free);
    ht_destroy(e->target_index, il_free);
    free(e->logs); free(e->alerts); free(e);
}

static IPProfile *ip_profile(Engine *e, const char *ip) {
    IPProfile *p = (IPProfile *)ht_get(e->ip_profiles, ip);
    if (!p) {
        p = (IPProfile *)calloc(1, sizeof *p);
        scopy(p->ip, ip); p->last_brute = -1;
        ht_put(e->ip_profiles, ip, p);
    }
    return p;
}
static UserProfile *user_profile(Engine *e, const char *user) {
    UserProfile *u = (UserProfile *)ht_get(e->user_profiles, user);
    if (!u) {
        u = (UserProfile *)calloc(1, sizeof *u);
        scopy(u->user, user);
        ht_put(e->user_profiles, user, u);
    }
    return u;
}
static void index_add(HashTable *t, const char *key, int idx) {
    IntList *l = (IntList *)ht_get(t, key);
    if (!l) { l = (IntList *)calloc(1, sizeof *l); ht_put(t, key, l); }
    il_push(l, idx);
}


const char *event_name(EventType t) {
    static const char *n[] = { "LOGIN_FAIL", "LOGIN_OK", "PORT_PROBE", "ACCESS_DENIED", "UNKNOWN" };
    return n[t];
}
const char *threat_name(ThreatType t) {
    switch (t) {
        case TH_BRUTE_FORCE:        return "BRUTE_FORCE";
        case TH_PORT_SCAN:          return "PORT_SCAN";
        case TH_UNAUTH_ACCESS:      return "UNAUTHORIZED_ACCESS";
        case TH_ACCOUNT_COMPROMISE: return "ACCOUNT_COMPROMISE";
    }
    return "?";
}

static void raise_alert(Engine *e, IPProfile *p, ThreatType type,
                        const LogEvent *ev, int count, int base, const char *fmt, ...) {
    if (e->nalerts == e->alertcap) {
        e->alertcap = e->alertcap ? e->alertcap * 2 : 16;
        e->alerts = (Alert *)realloc(e->alerts, e->alertcap * sizeof(Alert));
    }
    Alert *a = &e->alerts[e->nalerts];
    a->id = ++e->nalerts;                     
    a->type = type; a->ts = ev->ts; a->event_count = count;
    scopy(a->ip, ev->ip); scopy(a->user, ev->user); scopy(a->target, ev->target);
    a->severity = base + (p->alerts > 0 ? 1 : 0);   
    if (a->severity > 10) a->severity = 10;
    p->alerts++;
    p->threat_count[type]++;      
    e->threat_total[type]++;
    va_list ap; va_start(ap, fmt);
    vsnprintf(a->desc, sizeof a->desc, fmt, ap);
    va_end(ap);
    if (e->on_alert) e->on_alert(a, e->on_alert_ctx);   
}

static void analyze(Engine *e, const LogEvent *ev, IPProfile *p) {
    const Config *c = &e->cfg;
    switch (ev->type) {
    case EV_LOGIN_FAIL:
        ring_push(&p->fail_ring, ev->ts, 0);
        if (ring_count(&p->fail_ring, ev->ts, c->brute_win) >= c->brute_thresh) {
            raise_alert(e, p, TH_BRUTE_FORCE, ev, c->brute_thresh, 6,
                "%d failed logins from %s within %ds (last user: %s)",
                c->brute_thresh, ev->ip, c->brute_win, ev->user);
            p->last_brute = ev->ts;
            ring_clear(&p->fail_ring);          
        }
        break;
    case EV_LOGIN_OK:
        if (p->last_brute >= 0 && ev->ts - p->last_brute <= c->compromise_win) {
            raise_alert(e, p, TH_ACCOUNT_COMPROMISE, ev, 1, 9,
                "Successful login as '%s' from %s shortly after brute-force",
                ev->user, ev->ip);
            p->last_brute = -1;
        }
        break;
    case EV_PORT_PROBE:
        ring_push(&p->probe_ring, ev->ts, ev->port);
        {
            int d = ring_distinct_ports(&p->probe_ring, ev->ts, c->scan_win);
            if (d >= c->scan_thresh) {
                raise_alert(e, p, TH_PORT_SCAN, ev, d, 4,
                    "%d distinct ports probed on %s within %ds",
                    d, ev->target, c->scan_win);
                ring_clear(&p->probe_ring);
            }
        }
        break;
    case EV_ACCESS_DENIED:
        ring_push(&p->denied_ring, ev->ts, 0);
        if (ring_count(&p->denied_ring, ev->ts, c->unauth_win) >= c->unauth_thresh) {
            raise_alert(e, p, TH_UNAUTH_ACCESS, ev, c->unauth_thresh, 7,
                "%d denied access attempts to %s within %ds",
                c->unauth_thresh, ev->target, c->unauth_win);
            ring_clear(&p->denied_ring);
        }
        break;
    default: break;
    }
}



int engine_ingest(Engine *e, LogEvent ev) {
    if (e->nlogs == e->logcap) {
        e->logcap = e->logcap ? e->logcap * 2 : 64;
        e->logs = (LogEvent *)realloc(e->logs, e->logcap * sizeof(LogEvent));
    }
    
    if (e->nlogs > 0 && ev.ts < e->logs[e->nlogs - 1].ts) {
        ev.ts = e->logs[e->nlogs - 1].ts;
        e->late_events++;
    }
    int idx = e->nlogs;
    ev.seq = idx;
    e->logs[e->nlogs++] = ev;

    index_add(e->ip_index, ev.ip, idx);
    if (strcmp(ev.user, "-"))   index_add(e->user_index, ev.user, idx);
    if (strcmp(ev.target, "-")) index_add(e->target_index, ev.target, idx);

    IPProfile *p = ip_profile(e, ev.ip);
    if (p->total == 0) p->first_seen = ev.ts;
    p->last_seen = ev.ts; p->total++;
    switch (ev.type) {
        case EV_LOGIN_FAIL:    p->fails++;  break;
        case EV_LOGIN_OK:      p->oks++;    break;
        case EV_PORT_PROBE:    p->probes++; break;
        case EV_ACCESS_DENIED: p->denied++; break;
        default: break;
    }
    if (strcmp(ev.user, "-")) {
        UserProfile *u = user_profile(e, ev.user);
        if (u->total == 0) u->first_seen = ev.ts;
        u->last_seen = ev.ts; u->total++;
        scopy(u->last_ip, ev.ip);
        if (ev.type == EV_LOGIN_FAIL) u->fails++;
        if (ev.type == EV_LOGIN_OK)   u->oks++;
    }
    analyze(e, &ev, p);
    return idx;
}


static int parse_line(const char *line, LogEvent *ev) {
    char evs[32]; memset(ev, 0, sizeof *ev);
    if (sscanf(line, "%ld,%63[^,],%63[^,],%31[^,],%63[^,],%d",
               &ev->ts, ev->ip, ev->user, evs, ev->target, &ev->port) != 6)
        return 0;
    ev->type = EV_UNKNOWN;
    for (int t = 0; t < EV_UNKNOWN; t++)
        if (!strcmp(evs, event_name((EventType)t))) ev->type = (EventType)t;
    return 1;
}

static int cmp_ts(const void *a, const void *b) {
    const LogEvent *x = (const LogEvent *)a, *y = (const LogEvent *)b;
    if (x->ts != y->ts) return x->ts < y->ts ? -1 : 1;
    return x->seq - y->seq;
}

int engine_load_file(Engine *e, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    LogEvent *tmp = NULL; int n = 0, cap = 0, bad = 0, lineno = 0;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        lineno++;
        if (line[0] == '#' || line[0] == '\n') continue;
        LogEvent ev;
        if (!parse_line(line, &ev)) { bad++; continue; }
        ev.seq = lineno;
        if (n == cap) { cap = cap ? cap * 2 : 256; tmp = (LogEvent *)realloc(tmp, cap * sizeof *tmp); }
        tmp[n++] = ev;
    }
    fclose(f);
    qsort(tmp, n, sizeof *tmp, cmp_ts);         
    for (int i = 0; i < n; i++) engine_ingest(e, tmp[i]);
    free(tmp);
    if (bad) fprintf(stderr, "warning: skipped %d malformed line(s)\n", bad);
    return n;
}

void engine_set_alert_callback(Engine *e, AlertCallback cb, void *ctx) {
    e->on_alert = cb; e->on_alert_ctx = ctx;
}

int engine_ingest_line(Engine *e, const char *line) {
    char buf[512]; LogEvent ev;
    while (*line == ' ' || *line == '\t') line++;
    if (*line == 0 || *line == '#' || *line == '\n' || *line == '\r') return -1;
    if (strncmp(line, "now,", 4) == 0) {         
        snprintf(buf, sizeof buf, "%ld,%s", (long)time(NULL), line + 4);
        line = buf;
    }
    if (!parse_line(line, &ev)) return 0;
    engine_ingest(e, ev);
    return 1;
}


const IntList *search_by_ip(Engine *e, const char *ip)         { return (const IntList *)ht_get(e->ip_index, ip); }
const IntList *search_by_user(Engine *e, const char *u)        { return (const IntList *)ht_get(e->user_index, u); }
const IntList *search_by_target(Engine *e, const char *t)      { return (const IntList *)ht_get(e->target_index, t); }

const Alert *find_alert(Engine *e, int id) {
    int lo = 0, hi = e->nalerts - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (e->alerts[mid].id == id) return &e->alerts[mid];
        if (e->alerts[mid].id < id) lo = mid + 1; else hi = mid - 1;
    }
    return NULL;
}


static int lower_bound_ts(Engine *e, long t) {
    int lo = 0, hi = e->nlogs;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (e->logs[mid].ts < t) lo = mid + 1; else hi = mid;
    }
    return lo;
}

int search_time_range(Engine *e, long from, long to, int *lo) {
    int a = lower_bound_ts(e, from);
    int b = lower_bound_ts(e, to + 1);
    *lo = a;
    return b > a ? b - a : 0;
}


typedef struct { Engine *e; int by_target, min_events, groups; } CorrCtx;

static void corr_cb(const char *key, void *val, void *vctx) {
    CorrCtx *c = (CorrCtx *)vctx; IntList *l = (IntList *)val;
    const LogEvent *L = c->e->logs;
    long gap = c->e->cfg.session_gap;
    int i = 0;
    while (i < l->n) {
        int j = i;                       
        while (j + 1 < l->n && L[l->a[j + 1]].ts - L[l->a[j]].ts <= gap) j++;
        int cnt = j - i + 1;
        if (cnt >= c->min_events) {
            int by[EV_COUNT] = {0};
            HashTable *distinct = ht_create(8);
            for (int k = i; k <= j; k++) {
                const LogEvent *ev = &L[l->a[k]];
                by[ev->type]++;
                ht_put(distinct, c->by_target ? ev->ip : ev->target, (void *)1);
            }
            long t0 = L[l->a[i]].ts, t1 = L[l->a[j]].ts;
            printf("  %-18s t=%ld..%ld (%lds)  %2d events  [fail %d, ok %d, probe %d, denied %d]  distinct %s: %lu\n",
                   key, t0, t1, t1 - t0, cnt, by[EV_LOGIN_FAIL], by[EV_LOGIN_OK],
                   by[EV_PORT_PROBE], by[EV_ACCESS_DENIED],
                   c->by_target ? "sources" : "targets", (unsigned long)distinct->size);
            ht_destroy(distinct, NULL);
            c->groups++;
        }
        i = j + 1;
    }
}

int engine_correlate(Engine *e, int by_target, int min_events) {
    CorrCtx c = { e, by_target, min_events, 0 };
    printf("Correlated groups by %s (gap <= %lds, >= %d events):\n",
           by_target ? "target" : "source IP", e->cfg.session_gap, min_events);
    ht_foreach(by_target ? e->target_index : e->ip_index, corr_cb, &c);
    if (!c.groups) printf("  (none)\n");
    return c.groups;
}


void print_event(const LogEvent *ev) {
    printf("  t=%-8ld %-15s user=%-10s %-13s target=%-10s port=%d\n",
           ev->ts, ev->ip, ev->user, event_name(ev->type), ev->target, ev->port);
}
void print_alert(const Alert *a) {
    printf("  [#%d] sev=%2d %-20s t=%ld ip=%s user=%s\n        %s\n",
           a->id, a->severity, threat_name(a->type), a->ts, a->ip, a->user, a->desc);
}
void print_all_alerts(Engine *e) {
    printf("Alerts (%d):\n", e->nalerts);
    for (int i = 0; i < e->nalerts; i++) print_alert(&e->alerts[i]);
}
int print_ip_metrics(Engine *e, const char *ip) {
    IPProfile *p = (IPProfile *)ht_get(e->ip_profiles, ip);
    if (!p) return 0;
    printf("  IP %s: %d events (fail %d, ok %d, probe %d, denied %d), %d alert(s), seen %ld..%ld\n",
           p->ip, p->total, p->fails, p->oks, p->probes, p->denied, p->alerts,
           p->first_seen, p->last_seen);
    printf("    threats: brute-force %d, port-scan %d, unauthorized %d, compromise %d\n",
           p->threat_count[TH_BRUTE_FORCE], p->threat_count[TH_PORT_SCAN],
           p->threat_count[TH_UNAUTH_ACCESS], p->threat_count[TH_ACCOUNT_COMPROMISE]);
    return 1;
}
int print_user_metrics(Engine *e, const char *user) {
    UserProfile *u = (UserProfile *)ht_get(e->user_profiles, user);
    if (!u) return 0;
    printf("  User %s: %d events (fail %d, ok %d), last IP %s, seen %ld..%ld\n",
           u->user, u->total, u->fails, u->oks, u->last_ip, u->first_seen, u->last_seen);
    return 1;
}

void print_stats(Engine *e) {
    printf("  events: %d | IPs tracked: %lu | users tracked: %lu | alerts: %d | out-of-order clamped: %d\n",
           e->nlogs, (unsigned long)e->ip_profiles->size,
           (unsigned long)e->user_profiles->size, e->nalerts, e->late_events);
    printf("  alerts by type: brute-force %d, port-scan %d, unauthorized %d, compromise %d\n",
           e->threat_total[TH_BRUTE_FORCE], e->threat_total[TH_PORT_SCAN],
           e->threat_total[TH_UNAUTH_ACCESS], e->threat_total[TH_ACCOUNT_COMPROMISE]);
}
