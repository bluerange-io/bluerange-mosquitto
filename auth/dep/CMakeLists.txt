target_sources(AuthTest PUBLIC "cJSON.c"
                               "log.c"
                               "metrics.c")

target_include_directories(AuthTest PUBLIC .)
