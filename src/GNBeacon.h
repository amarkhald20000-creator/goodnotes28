//
//  GNBeacon.h
//  The one part of this dylib that is not allowed to fail silently.
//
//  Every previous version logged through Foundation (NSSearchPathForDirectories-
//  InDomains -> NSString -> open()) and buffered nothing, so when the app died
//  during launch the two facts we needed - "did our constructor run" and "what
//  was thrown" - could both be absent, and there was no way to tell a missing
//  log from a dylib that never loaded.
//
//  This header is deliberately Foundation free. Nothing in GNBeacon.m sends an
//  Objective-C message, allocates, or takes a lock that another framework could
//  already hold during dyld init. It opens up to four log files with open(2),
//  writes with write(2), and fsyncs every line.
//
#pragma once

#include <stddef.h>

/// Bump on every delivery. It is the first line of every beacon so a log that
/// turns up later can never be mistaken for a different build.
#define GN_UNLOCK_VERSION "27"

#ifdef __cplusplus
extern "C" {
#endif

/// Must be the first statement of the dylib constructor. Opens every log sink
/// it can, then writes a banner naming the sinks that actually opened.
///
/// Returns nothing and never fails: if no file can be opened the banner still
/// goes to stderr, and GNBeaconSinkCount() returns 0 so the caller can say so
/// out loud instead of pretending it logged.
void GNBoot(void);

/// Appends one fsync'd line to every open sink and to stderr.
/// printf format, C strings only - do not pass an NSString.
void GNBeaconLine(const char *fmt, ...) __attribute__((format(__printf__, 1, 2)));

/// Number of log files that are actually open. 0 means the filesystem refused
/// every candidate and only stderr has anything.
int GNBeaconSinkCount(void);

/// Path of the first sink that opened, or "" when none did.
const char *GNBeaconPrimaryPath(void);

/// Milliseconds since GNBoot() started, for every line's timestamp.
double GNBeaconUptimeMs(void);

/// Container home as the process sees it ($HOME), or "" if unset.
const char *GNBeaconHome(void);

#ifdef __cplusplus
}
#endif
