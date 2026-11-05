//
//  GNBeacon.m
//  Foundation-free, unbuffered, fsync'd logging that survives a launch crash.
//
//  Design rules, each one a bug this project already paid for:
//
//    1. No Foundation. Not one message send. A dylib constructor runs during
//       dyld init; anything that can lazily initialise a class or take a
//       framework lock is a liability at that point. open/write/fsync cannot
//       surprise us.
//
//    2. $HOME, not NSSearchPathForDirectoriesInDomains. The previous builds
//       asked Foundation for Documents. If that ever answers a path the
//       sandbox then refuses, every line is lost and the symptom is
//       indistinguishable from "the dylib never loaded". $HOME is what the
//       kernel actually gave this process.
//
//    3. Four sinks, not one. The same line goes to Documents, the container
//       root, tmp and Library/Caches. Whichever one the user can reach with
//       their file manager, has the log.
//
//    4. fsync after every line. The crash we are chasing happens a few hundred
//       milliseconds in; a buffered log would be empty exactly then.
//
//    5. The banner names the sinks that opened, and GNBeaconSinkCount() is
//       logged by the caller. "I wrote a log" and "the log exists" are
//       different claims and this file refuses to conflate them.
//

#include "GNBeacon.h"

#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define GN_SINK_MAX      4
#define GN_PATH_MAX      320
#define GN_LINE_MAX      1400

static int             gSinkFD[GN_SINK_MAX];
static char            gSinkPath[GN_SINK_MAX][GN_PATH_MAX];
static int             gSinkCount = 0;
static char            gPrimaryPath[GN_PATH_MAX];
static char            gHome[GN_PATH_MAX];
static int             gBooted = 0;
static pthread_mutex_t gBeaconLock = PTHREAD_MUTEX_INITIALIZER;
static struct timespec gBootTime;
static int             gHaveBootTime = 0;

#pragma mark - Small C helpers

static void GNStrCopy(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/// Joins two path components with exactly one slash. Returns NO on overflow
/// rather than truncating into a different path - a truncated path is a log
/// that silently lands somewhere else.
static int GNPathJoin(char *dst, size_t cap, const char *a, const char *b) {
    if (!dst || cap == 0) return 0;
    if (!a || !b) { dst[0] = '\0'; return 0; }
    size_t la = strlen(a);
    size_t lb = strlen(b);
    int needSlash = (la > 0 && a[la - 1] != '/');
    size_t total = la + (size_t)needSlash + lb;
    if (total + 1 > cap) { dst[0] = '\0'; return 0; }
    memcpy(dst, a, la);
    size_t off = la;
    if (needSlash) dst[off++] = '/';
    memcpy(dst + off, b, lb);
    dst[off + lb] = '\0';
    return 1;
}

static double GNUptimeNowMs(void) {
    if (!gHaveBootTime) return 0.0;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0.0;
    return (double)(now.tv_sec - gBootTime.tv_sec) * 1000.0 +
           (double)(now.tv_nsec - gBootTime.tv_nsec) / 1000000.0;
}

static void GNBeaconTimestamp(char *buf, size_t cap) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tmv;
    time_t t = tv.tv_sec;
    localtime_r(&t, &tmv);
    snprintf(buf, cap, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (int)(tv.tv_usec / 1000));
}

#pragma mark - Sinks

static void GNOpenSink(const char *path) {
    if (!path || !path[0]) return;
    if (gSinkCount >= GN_SINK_MAX) return;

    for (int i = 0; i < gSinkCount; i++) {
        if (strcmp(gSinkPath[i], path) == 0) return;   // already open
    }

    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) return;

    gSinkFD[gSinkCount] = fd;
    GNStrCopy(gSinkPath[gSinkCount], GN_PATH_MAX, path);
    gSinkCount++;

    if (!gPrimaryPath[0]) GNStrCopy(gPrimaryPath, GN_PATH_MAX, path);
}

static void GNWriteAll(int fd, const char *bytes, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, bytes + off, len - off);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR)) continue;
            break;
        }
        off += (size_t)n;
    }
}

#pragma mark - Public

double GNBeaconUptimeMs(void) {
    return GNUptimeNowMs();
}

int GNBeaconSinkCount(void) {
    return gSinkCount;
}

const char *GNBeaconPrimaryPath(void) {
    return gPrimaryPath;
}

const char *GNBeaconHome(void) {
    return gHome;
}

void GNBeaconLine(const char *fmt, ...) {
    char body[GN_LINE_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    char ts[40];
    GNBeaconTimestamp(ts, sizeof(ts));

    char line[GN_LINE_MAX + 128];
    int n = snprintf(line, sizeof(line), "%s +%8.1fms pid=%d  %s\n",
                     ts, GNUptimeNowMs(), (int)getpid(), body);
    if (n <= 0) return;
    if ((size_t)n > sizeof(line) - 1) n = (int)sizeof(line) - 1;

    pthread_mutex_lock(&gBeaconLock);

    if (gSinkCount == 0) {
        // Retry once: the container may not have existed at constructor time.
        const char *home = gHome;
        if (home && home[0]) {
            char path[GN_PATH_MAX];
            if (GNPathJoin(path, sizeof(path), home, "Documents/gnunlock.log")) GNOpenSink(path);
        }
    }

    for (int i = 0; i < gSinkCount; i++) {
        GNWriteAll(gSinkFD[i], line, (size_t)n);
        fsync(gSinkFD[i]);
    }

    pthread_mutex_unlock(&gBeaconLock);

    GNWriteAll(2, line, (size_t)n);   // stderr, always
}

void GNBoot(void) {
    if (gBooted) return;
    gBooted = 1;

    if (clock_gettime(CLOCK_MONOTONIC, &gBootTime) == 0) gHaveBootTime = 1;

    const char *home = getenv("HOME");
    if (home) GNStrCopy(gHome, sizeof(gHome), home);

    // Four candidates. Documents first (it is the one a file manager opens by
    // default), then the container root, tmp, and Caches. Any one surviving is
    // enough; all four failing means the sandbox gave us nothing and stderr is
    // the only trace.
    if (gHome[0]) {
        char path[GN_PATH_MAX];
        if (GNPathJoin(path, sizeof(path), gHome, "Documents/gnunlock.log")) GNOpenSink(path);
        if (GNPathJoin(path, sizeof(path), gHome, "gnunlock.log"))           GNOpenSink(path);
        if (GNPathJoin(path, sizeof(path), gHome, "tmp/gnunlock.log"))       GNOpenSink(path);
        if (GNPathJoin(path, sizeof(path), gHome, "Library/Caches/gnunlock.log")) GNOpenSink(path);
    }
    GNOpenSink("/tmp/gnunlock.log");

    GNBeaconLine("================================================");
    GNBeaconLine("GNUnlock v12 beacon - constructor reached");
    GNBeaconLine("if you are reading this file, the dylib loaded and its constructor ran");
    GNBeaconLine("version   : %s", GN_UNLOCK_VERSION);
    GNBeaconLine("uid/pid   : %d / %d", (int)getuid(), (int)getpid());
    GNBeaconLine("HOME      : %s", gHome[0] ? gHome : "(unset)");
    GNBeaconLine("sinks     : %d open", gSinkCount);
    for (int i = 0; i < gSinkCount; i++) {
        GNBeaconLine("  sink[%d] : %s", i, gSinkPath[i]);
    }
    if (gSinkCount == 0) {
        GNBeaconLine("WARNING   : no log file could be opened - only stderr has this text.");
        GNBeaconLine("WARNING   : if the app dies, look for these lines in the device console.");
    }

    // Executable path and image head: the two facts that make a bare offset in
    // a crash report meaningful.
    char exe[1024];
    uint32_t exeSize = (uint32_t)sizeof(exe);
    if (_NSGetExecutablePath(exe, &exeSize) == 0) {
        GNBeaconLine("executable: %s", exe);
    }

    uint32_t images = _dyld_image_count();
    GNBeaconLine("dyld      : %u images", images);
    for (uint32_t i = 0; i < images && i < 4; i++) {
        const char *name = _dyld_get_image_name(i);
        GNBeaconLine("  image[%u] : %s", i, name ? name : "(null)");
    }

    GNBeaconLine("================================================");
}
