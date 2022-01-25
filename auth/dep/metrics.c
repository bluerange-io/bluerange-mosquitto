#ifndef AUTH_TEST_ENABLED
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <curl/curl.h>
#else
#include <assert.h>
#include "testmock.h"
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <ctype.h>

#include "metrics.h"

#define BUFLEN 100

#define SYS_TREE_QOS 2

static Metrics last_metrics = { 0 };

#define MAX_REQUEST_TIMES 128
static double last_request_times[MAX_REQUEST_TIMES] = { .0 };
static volatile double sum_request_times = .0;

void metrics_server_request(Metrics* metrics, time_t end, time_t beginning)
{
    double request_time = difftime(end, beginning); // https://www.cplusplus.com/reference/ctime/difftime/
    size_t request_count = metrics->server_request_count++;
    size_t request_index = request_count % MAX_REQUEST_TIMES;
    double request_last = last_request_times[request_index];
    last_request_times[request_index] = request_time;
    sum_request_times -= request_last;
    sum_request_times += request_time;
    metrics->server_request_time = sum_request_times / (request_count < MAX_REQUEST_TIMES ? request_count + 1 : MAX_REQUEST_TIMES);
}

void metrics_update(Metrics* metrics)
{
    char buf[BUFLEN];
    int len;

    // inspired by https://github.com/eclipse/mosquitto/blob/master/src/sys_tree.c#L155
    if (last_metrics.logins_succeeded_count != metrics->logins_succeeded_count) {
        len = snprintf(buf, BUFLEN, "%" PRIuFAST64, last_metrics.logins_succeeded_count = metrics->logins_succeeded_count);
        mosquitto_broker_publish_copy(NULL, "$SYS/broker/auth/logins/succeeded/count", len, buf, SYS_TREE_QOS, 1, NULL);
    }
    if (last_metrics.logins_failed_count != metrics->logins_failed_count) {
        len = snprintf(buf, BUFLEN, "%" PRIuFAST64, last_metrics.logins_failed_count = metrics->logins_failed_count);
        mosquitto_broker_publish_copy(NULL, "$SYS/broker/auth/logins/failed/count", len, buf, SYS_TREE_QOS, 1, NULL);
    }
    if (last_metrics.logins_user_count != metrics->logins_user_count) {
        len = snprintf(buf, BUFLEN, "%" PRIuFAST64, last_metrics.logins_user_count = metrics->logins_user_count);
        mosquitto_broker_publish_copy(NULL, "$SYS/broker/auth/logins/user/count", len, buf, SYS_TREE_QOS, 1, NULL);
    }

    if (last_metrics.server_request_count != metrics->server_request_count) {
        len = snprintf(buf, BUFLEN, "%" PRIuFAST64, last_metrics.server_request_count = metrics->server_request_count);
        mosquitto_broker_publish_copy(NULL, "$SYS/broker/auth/server/request/count", len, buf, SYS_TREE_QOS, 1, NULL);
    }
    if (last_metrics.server_request_time != metrics->server_request_time) {
        len = snprintf(buf, BUFLEN, "%.6f", last_metrics.server_request_time = metrics->server_request_time); // up to nanos
        while(len > 1 && buf[len-1] == '0' && isdigit(buf[len-2])) {
            // remove trailing zero unless immediately followed by the decimal point
            buf[--len] = '\0'; // terminate for safety
        }
        mosquitto_broker_publish_copy(NULL, "$SYS/broker/auth/server/request/time", len, buf, SYS_TREE_QOS, 1, NULL);
    }

    if (last_metrics.blacklist_length != metrics->blacklist_length) {
        len = snprintf(buf, BUFLEN, "%" PRIuFAST64, last_metrics.blacklist_length = metrics->blacklist_length);
        mosquitto_broker_publish_copy(NULL, "$SYS/broker/auth/blacklist/length", len, buf, SYS_TREE_QOS, 1, NULL);
    }
    if (last_metrics.duplicatelist_length != metrics->duplicatelist_length) {
        len = snprintf(buf, BUFLEN, "%" PRIuFAST64, last_metrics.duplicatelist_length = metrics->duplicatelist_length);
        mosquitto_broker_publish_copy(NULL, "$SYS/broker/auth/duplicatelist/length", len, buf, SYS_TREE_QOS, 1, NULL);
    }
}
