#pragma once

typedef enum
{
	LOG_PRIORITY_FATAL   = 0,
	LOG_PRIORITY_ERROR   = 1,
	LOG_PRIORITY_WARNING = 2,
	LOG_PRIORITY_INFO    = 3,
	LOG_PRIORITY_TRACE   = 4,
} LogPriority;

void setAuthLogPriority(LogPriority logPrio);
LogPriority getAuthLogPriority();
void authLog(LogPriority logPrio, const char *fmt, ...);
