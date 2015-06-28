#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <errno.h>
#include "ename.c.inc"
#include <sys/time.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>
#include "select_server.h"

char *list[] = {
    "tw1.vpnplease.com",
    "sg1.vpnplease.com",
    "sg2.vpnplease.com",
    "jp1.vpnplease.com",
    "jp2.vpnplease.com",
    "jp3.vpnplease.com",
    "us1.vpnplease.com",
    "us2.vpnplease.com",
    "us3.vpnplease.com",
    "us4.vpnplease.com",
    "us5.vpnplease.com",
    "uk1.vpnplease.com",
    "hk1.vpnplease.com",
    "hk2.vpnplease.com"
};
int listlen = sizeof(list) / sizeof(char *);
#define RETRY_CNT 3
long *results;

void outputError(bool useErr, int err, bool flushStdout, const char *format, va_list ap) {
#define BUF_SIZE 500
    char buf[BUF_SIZE], userMsg[BUF_SIZE], errText[BUF_SIZE];

    vsnprintf(userMsg, BUF_SIZE, format, ap);

    if (useErr)
        snprintf(errText, BUF_SIZE, " [%s %s]", (err > 0 && err <= MAX_ENAME) ?
                ename[err] : "?UNKNOWN?", strerror(err));
    else
        snprintf(errText, BUF_SIZE, ":");

    snprintf(buf, BUF_SIZE, "ERROR%s %s\n", errText, userMsg);

    if (flushStdout)
        fflush(stdout);       /* Flush any pending stdout */
    fputs(buf, stderr);
    fflush(stderr);           /* In case stderr is not line-buffered */
}

void errExit(const char *format, ...) {
    va_list argList;

    va_start(argList, format);
    outputError(true, errno, true, format, argList);
    va_end(argList);

    exit(EXIT_FAILURE);
}

void errExitEN(int errnum, const char *format, ...) {
    va_list argList;

    va_start(argList, format);
    outputError(true, errnum, true, format, argList);
    va_end(argList);

    exit(EXIT_FAILURE);
}

void fatal(const char *format, ...) {
    va_list argList;

    va_start(argList, format);
    outputError(false, 0, true, format, argList);
    va_end(argList);

    exit(EXIT_FAILURE);
}

int in_cksum(unsigned short *buf, int sz) {
  int nleft = sz;
  int sum = 0;
  unsigned short *w = buf;
  unsigned short ans = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(unsigned char *) (&ans) = *(unsigned char *) w;
    sum += ans;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  ans = ~sum;
  return (ans);
}

long gettime() {
    struct timeval t;
    gettimeofday(&t, NULL);
    return t.tv_sec * 1e6 + t.tv_usec;
}

int comp(const void *plefti, const void *prighti) {
    int lefti, righti;
    lefti  = *(int *) plefti;
    righti = *(int *) prighti;
    return results[lefti] - results[righti];
}

long ping_server(const char *host) {
    struct hostent *ent;
    struct sockaddr_in pingaddr, from;
    struct icmp *pkt;
    struct timeval tv;
    struct ip *iphdr;
    int pingsockfd;
    size_t fromlen = sizeof(from);
    ssize_t c;
    long begtime, endtime;
    char packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];

    if ((pingsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        return -1;
    setuid(getuid());

    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if (setsockopt(pingsockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) == -1 ||
        setsockopt(pingsockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) == -1)
        return -1;

    memset(&pingaddr, 0, sizeof(struct sockaddr_in));

    pingaddr.sin_family = AF_INET;
    if ((ent = gethostbyname(host)) == NULL) {
        errno = EHOSTDOWN;
        return -1;
    }
    memcpy(&pingaddr.sin_addr, ent->h_addr, sizeof(pingaddr.sin_addr));

    pkt = (struct icmp *) packet;
    memset(pkt, 0, sizeof(packet));
    pkt->icmp_type = ICMP_ECHO;
    pkt->icmp_cksum = in_cksum((unsigned short *) pkt, sizeof(packet));

    c = sendto(pingsockfd, packet, sizeof(packet), 0, (struct sockaddr *) &pingaddr, sizeof(struct sockaddr_in));
    if (c < 0 || c != sizeof(packet)) return -1;

    for (;;) {
        begtime = gettime();
        if ((c = recvfrom(pingsockfd, packet, sizeof(packet), 0, (struct sockaddr *) &from, (socklen_t *) &fromlen)) < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        endtime = gettime();
        if (c >= 76) {
            iphdr = (struct ip *) packet;
            pkt = (struct icmp *) (packet + (iphdr->ip_hl << 2));
            if (pkt->icmp_type == ICMP_ECHOREPLY) break;
        }
    }
    return endtime - begtime;
}

long ping(const char *host) {
    int j;
    long t, times[RETRY_CNT], sum;
    for (j = 1; j <= RETRY_CNT; ++j) {
        if ((t = ping_server(host)) == -1) {
            switch (errno) {
            case EAGAIN:
                fprintf(stderr, "%s[%d]: Ping Timeout\n", host, j);
                times[j - 1] = 2 * 1e6;
                break;
            case EHOSTDOWN:
                fprintf(stderr, "%s[%d]: Cannot resolve %s\n", host, j, host);
                return -1;
            default:
                errExit("ping server error");
            }
        } else {
            times[j - 1] = t;
            printf("%s[%d]: %ld\n", host, j, t);
        }
    }
    sum = 0;
    for (j = 0; j < RETRY_CNT; ++j)
        sum += times[j];
    return sum / RETRY_CNT;
}

#define TOPCNT 3
int main(int argc, char const *argv[]) {
    int i, *indices;
    results = calloc(listlen, sizeof(long));
    indices = calloc(listlen, sizeof(int));
    for (i = 0; i < listlen; ++i) {
        if ((results[i] = ping(list[i])) == -1)
            results[i] = LONG_MAX;
    }
    for (i = 0; i < listlen; ++i)
        indices[i] = i;
    qsort(indices, listlen, sizeof(indices[0]), comp);

    for (i = 0; i < TOPCNT; ++i)
        printf("Top %d: %s\n", i + 1, list[indices[i]]);

    free(results);
    free(indices);
    return 0;
}
