/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/poll.h>
#include <unistd.h>
#include <limits.h>
#include <netinet/in.h>
#include "eapp.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BH_PLATFORM_PENGLAI
#define BH_PLATFORM_PENGLAI
#endif

#define _STACK_SIZE_ADJUSTMENT (32 * 1024)

/* Stack size of applet threads's native part.  */
#define BH_APPLET_PRESERVED_STACK_SIZE (8 * 1024 + _STACK_SIZE_ADJUSTMENT)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 0

typedef pthread_t korp_thread;
typedef pthread_t korp_tid;
typedef pthread_mutex_t korp_mutex;
typedef pthread_cond_t korp_cond;
typedef unsigned int korp_sem;

typedef int (*os_print_function_t)(const char *message);

void
os_set_print_function(os_print_function_t pf);

char *
strcpy(char *dest, const char *src);

#define PENGLAI_PG_SIZE 4096

/* math functions which are not provided by os */
double atan(double x);
double atan2(double y, double x);
double sqrt(double x);
double floor(double x);
double ceil(double x);
double fmin(double x, double y);
double fmax(double x, double y);
double rint(double x);
double fabs(double x);
double trunc(double x);
float floorf(float x);
float ceilf(float x);
float fminf(float x, float y);
float fmaxf(float x, float y);
float rintf(float x);
float truncf(float x);
int signbit(double x);
int isnan(double x);
double pow(double x, double y);
double scalbn(double x, int n);

#ifdef __cplusplus
}
#endif

#endif /* end of _PLATFORM_INTERNAL_H */
