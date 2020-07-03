
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#include "log.h"

static LogPriority logPriority = LOG_PRIORITY_INFO;

void setAuthLogPriority(LogPriority logPrio)
{
	logPriority = logPrio;
}

LogPriority getAuthLogPriority()
{
	return logPriority;
}

void authLog(LogPriority logPrio, const char *fmt, ...)
{
	if (logPrio > logPriority && logPrio != LOG_PRIORITY_FATAL) return;

	va_list va;
	long long now = (long long)time(NULL);

	const char* logPrioString = "";
	switch (logPrio)
	{
	case LOG_PRIORITY_FATAL:   logPrioString = "FATAL  "; break;
	case LOG_PRIORITY_ERROR:   logPrioString = "ERROR  "; break;
	case LOG_PRIORITY_WARNING: logPrioString = "WARNING"; break;
	case LOG_PRIORITY_INFO:    logPrioString = "INFO   "; break;
	case LOG_PRIORITY_TRACE:   logPrioString = "TRACE  "; break;
	default:                   logPrioString = "UNKNOWN"; break;
	}

	va_start(va, fmt);
	fprintf (stderr, "%s (%lld) --- ", logPrioString, now);
	vfprintf(stderr, fmt, va);
	fprintf (stderr, "\n");
	fflush  (stderr);
	va_end(va);

	if (logPrio == LOG_PRIORITY_FATAL)
	{
		exit(1);
	}
}
