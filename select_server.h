#ifndef _SELECT_SERVER_H
#define _SELECT_SERVER_H

#include <stdbool.h>

#define DEFDATALEN      56
#define MAXIPLEN        60
#define MAXICMPLEN      76

static void outputError(bool useErr, int err, bool flushStdout, const char *format, va_list ap);
static void errExit(const char *format, ...);
static void errExitEN(int errnum, const char *format, ...);
static void fatal(const char *format, ...);

static int in_cksum(unsigned short *buf, int sz);
static long gettime(void);
static int comp(const void *left, const void *right);

static long ping_server(const char *host);
static long ping(const char *host);

#endif
