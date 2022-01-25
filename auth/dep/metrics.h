#pragma once

#include <stdint.h>

#define AMOUNT_OF_SERVER_REQUESTS (64)

typedef struct Metrics {
    uint_fast64_t logins_succeeded_count;
    uint_fast64_t logins_failed_count;
    uint_fast64_t logins_user_count;

    uint_fast64_t server_request_count;
    double server_request_time;

    uint_fast64_t blacklist_length;
    uint_fast64_t duplicatelist_length;
} Metrics;

void metrics_server_request(Metrics* metrics, time_t end, time_t beginning);
void metrics_update(Metrics* metrics);
