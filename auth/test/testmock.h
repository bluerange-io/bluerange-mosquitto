/*
* Copyright 2020 M-Way Solutions GmbH
* 
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
* 
*     http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#pragma once

#define MOSQ_ERR_SUCCESS 0
#define MOSQ_AUTH_PLUGIN_VERSION 1
#define MOSQ_ERR_UNKNOWN 2
#define MOSQ_ERR_ACL_DENIED 3
#define MOSQ_ERR_AUTH 4

#define MOSQ_ACL_READ 1000
#define MOSQ_ACL_WRITE 1001
#define MOSQ_ACL_SUBSCRIBE 1002

#define CURLE_OK 0
#define CURLOPT_URL 2000
#define CURLOPT_POST 2001
#define CURLOPT_POSTFIELDS 2002
#define CURLOPT_TIMEOUT 2003
#define CURLOPT_WRITEFUNCTION 2004
#define CURLOPT_WRITEDATA 2005
#define CURLINFO_RESPONSE_CODE 2006
#define CURLINFO_CONTENT_TYPE 2007
#define CURLE_SOME_MOCK_ERROR 2008

#define false 0
#define true 1
typedef int bool;

struct mosquitto_opt
{
	const char* key;
	const char* value;
};

struct mosquitto_acl_msg
{
	const char* topic;
};

typedef struct
{
	void* writeData;
	void* writeFunction;
}CURL;

CURL* curl_easy_init();
const char* curl_easy_escape(CURL* curl, const char*s, int l);
int curl_easy_setopt(CURL* c, int o, void *p);
int curl_easy_perform(CURL* c);
void curl_easy_cleanup(CURL* c);
int curl_easy_getinfo(CURL* c, int type, void* data);

struct mosquitto
{
	const char* username;
	const char* password;
};

int mosquitto_disconnect(struct mosquitto* mosq);
const char* mosquitto_client_username(struct mosquitto* mosq);
int mosquitto_topic_matches_sub(const char* sub, const char* topic, bool* result);
const char* mosquitto_client_id(const struct mosquitto* mosq);
int mosquitto_sub_topic_check(const char* topic);
int mosquitto_pub_topic_check(const char* topic);
