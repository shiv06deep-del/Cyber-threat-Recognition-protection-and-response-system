#ifndef _WIN32
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L      /* for nanosleep under -std=c99 */
#endif
#endif

#include "detection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
static void sleep_ms(int ms) { Sleep(ms); }
#else
#include <time.h>
static void sleep_ms(int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}
#endif

/* ------------------------------------------------------------------ */
/*  helpers                                                            */
/* ------------------------------------------------------------------ */
static void ask(const char *prompt, char *buf, size_t n) {
    printf("%s", prompt); fflush(stdout);
    if (!fgets(buf, (int)n, stdin)) { buf[0] = 0; return; }
    buf[strcspn(buf, "\r\n")] = 0;
}

static void show_events(Engine *e, const IntList *l, const char *what) {
    if (!l) { printf("  no events for %s\n", what); return; }
    printf("  %d event(s) for %s:\n", l->n, what);
    for (int i = 0; i < l->n; i++) print_event(&e->logs[l->a[i]]);
}

/* REAL-TIME ALERT: engine calls this the instant a rule fires */
static void on_alert(const Alert *a, void *ctx) {
    (void)ctx;
    printf("\n  >>> REAL-TIME ALERT <<<\n");
    print_alert(a);
    printf("\n");
    fflush(stdout);
}

/* feed one live event (timestamp "now") and show it */
static void feed(Engine *e, const char *line, int delay_ms) {
    printf("  <- %s\n", line);
    fflush(stdout);
    engine_ingest_line(e, line);
    if (delay_ms > 0) sleep_ms(delay_ms);
}

/* ------------------------------------------------------------------ */
/*  live attack simulation                                             */
/* ------------------------------------------------------------------ */
static void simulate(Engine *e) {
    char line[128];
    printf("  --- simulating live traffic (alerts appear as they happen) ---\n");
    feed(e, "now,10.0.0.5,alice,LOGIN_OK,web-01,22", 500);

    printf("  [phase 1] brute-force on db-01\n");
    for (int i = 0; i < 6; i++) feed(e, "now,198.51.100.99,root,LOGIN_FAIL,db-01,22", 300);
    feed(e, "now,198.51.100.99,root,LOGIN_OK,db-01,22", 500);

    printf("  [phase 2] port scan on srv-01\n");
    for (int p = 0; p < 12; p++) {
        snprintf(line, sizeof line, "now,198.51.100.77,-,PORT_PROBE,srv-01,%d", 20 + p * 7);
        feed(e, line, 150);
    }

    printf("  [phase 3] unauthorized access to /admin\n");
    for (int i = 0; i < 3; i++) feed(e, "now,192.0.2.88,guest,ACCESS_DENIED,/admin,443", 400);
    printf("  --- simulation finished ---\n");
}

/* ------------------------------------------------------------------ */
/*  follow a log file as it grows (like tail -f)                       */
/* ------------------------------------------------------------------ */
static volatile sig_atomic_t stop_flag = 0;
static void on_sigint(int sig) { (void)sig; stop_flag = 1; }

static void follow_file(Engine *e, const char *path, int from_start) {
    FILE *f = fopen(path, "r");
    if (!f) { printf("  cannot open %s\n", path); return; }
    if (!from_start) fseek(f, 0, SEEK_END);
    printf("  watching %s ... append lines to it; Ctrl+C to stop\n", path);

    char line[512], acc[1024];
    size_t alen = 0;
    long processed = 0;
    stop_flag = 0;
    signal(SIGINT, on_sigint);

    while (!stop_flag) {
        if (fgets(line, sizeof line, f)) {
            size_t n = strlen(line);
            if (alen + n >= sizeof acc) { alen = 0; continue; }   /* drop absurd line */
            memcpy(acc + alen, line, n); alen += n; acc[alen] = 0;
            if (acc[alen - 1] == '\n') {                          /* complete line */
                if (acc[0] != '\n' && acc[0] != '\r' && acc[0] != '#') {
                    printf("  <- %s", acc); fflush(stdout);       /* show event first */
                }
                int r = engine_ingest_line(e, acc);               /* alert prints here */
                if (r == 1)      processed++;
                else if (r == 0) printf("  (malformed line skipped)\n");
                alen = 0;
            }
        } else {
            clearerr(f);                  /* EOF: wait for the writer */
            sleep_ms(300);
        }
    }
    signal(SIGINT, SIG_DFL);
    fclose(f);
    printf("\n  stopped; %ld live event(s) processed\n", processed);
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv) {
    Engine *e = engine_create();

    if (argc > 1) {                       /* optional history file */
        int n = engine_load_file(e, argv[1]);
        if (n < 0) fprintf(stderr, "cannot open %s (starting empty)\n", argv[1]);
        else printf("Loaded %d historical events from %s -> %d alert(s)\n", n, argv[1], e->nalerts);
    }
    engine_set_alert_callback(e, on_alert, NULL);   /* from now on: real-time */

    char buf[128];
    for (;;) {
        printf("\n --- Detection Engine (real-time) ---\n"
               " 1) All alerts          2) Search by IP        3) Search by username\n"
               " 4) Search threat ID    5) Time range          6) IP metrics\n"
               " 7) User metrics        8) Correlate by IP     9) Correlate by target\n"
               "10) Enter live event   11) Live attack demo   12) Follow a log file\n"
               "13) Statistics          0) Exit\n> ");
        fflush(stdout);
        if (!fgets(buf, sizeof buf, stdin)) break;
        char *end; long ch = strtol(buf, &end, 10);
        if (end == buf) { printf("  invalid choice\n"); continue; }
        if (ch == 0) break;

        char q[128];
        switch (ch) {
        case 1: print_all_alerts(e); break;
        case 2: ask("IP: ", q, sizeof q);   show_events(e, search_by_ip(e, q), q); break;
        case 3: ask("User: ", q, sizeof q); show_events(e, search_by_user(e, q), q); break;
        case 4: {
            ask("Threat ID: ", q, sizeof q);
            const Alert *a = find_alert(e, atoi(q));
            if (a) print_alert(a); else printf("  no such threat\n");
            break; }
        case 5: {
            char q2[128]; int lo;
            ask("From (epoch s): ", q, sizeof q); ask("To   (epoch s): ", q2, sizeof q2);
            int cnt = search_time_range(e, atol(q), atol(q2), &lo);
            printf("  %d event(s) in range\n", cnt);
            for (int i = 0; i < cnt; i++) print_event(&e->logs[lo + i]);
            break; }
        case 6: ask("IP: ", q, sizeof q);   if (!print_ip_metrics(e, q)) printf("  unknown IP\n"); break;
        case 7: ask("User: ", q, sizeof q); if (!print_user_metrics(e, q)) printf("  unknown user\n"); break;
        case 8: engine_correlate(e, 0, 3); break;
        case 9: engine_correlate(e, 1, 3); break;
        case 10: {
            char ip[STR_LEN], user[STR_LEN], ev[32], target[STR_LEN], line[256]; int port;
            ask("Enter: ip user EVENT target port   (use - for none)\n"
                "EVENT = LOGIN_FAIL | LOGIN_OK | PORT_PROBE | ACCESS_DENIED\n> ", q, sizeof q);
            if (sscanf(q, "%63s %63s %31s %63s %d", ip, user, ev, target, &port) != 5) {
                printf("  expected 5 fields\n"); break;
            }
            snprintf(line, sizeof line, "now,%s,%s,%s,%s,%d", ip, user, ev, target, port);
            engine_ingest_line(e, line);
            printf("  event processed (total alerts so far: %d)\n", e->nalerts);
            break; }
        case 11: simulate(e); break;
        case 12: {
            char yn[16];
            ask("Log file to watch: ", q, sizeof q);
            ask("Read existing lines first? (y/n): ", yn, sizeof yn);
            follow_file(e, q, yn[0] == 'y' || yn[0] == 'Y');
            break; }
        case 13: print_stats(e); break;
        default: printf("  invalid choice\n");
        }
    }
    engine_destroy(e);
    return 0;
}
