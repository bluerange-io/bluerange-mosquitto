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

#include "testmock.h"
#include "log.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef size_t curlCallbackFunc(void*, size_t, size_t, void*);

CURL * curl_easy_init()
{
	static CURL mockCurl;
	memset(&mockCurl, 0, sizeof(mockCurl));
	return &mockCurl;
}

const char * curl_easy_escape(CURL * curl, const char * s, int l)
{
	return s;
}

int curl_easy_setopt(CURL * c, int o, void *p)
{
	if (o == CURLOPT_WRITEDATA)
	{
		c->writeData = p;
	}
	else if (o == CURLOPT_WRITEFUNCTION)
	{
		c->writeFunction = p;
	}
	return CURLE_OK;
}

int curl_easy_perform(CURL * c)
{
	char data[] = "{\"apiVersion\":\"1\",\"aclEntries\":{\"rltn-iot/2A922016-2AB5-45CB-8A8F-E2CF7BE614A8/#\":\"rws\",\"rltn-mqtt/2A922016-2AB5-45CB-8A8F-E2CF7BE614A8/#\":\"rws\",\"rltn-mdm/2A922016-2AB5-45CB-8A8F-E2CF7BE614A8/#\":\"rws\"},\"superuser\":false}";
	size_t processedBytes = ((curlCallbackFunc*)c->writeFunction)(data, strlen(data), 1, c->writeData);
	assert(processedBytes == strlen(data));
	return CURLE_OK;
}

void curl_easy_cleanup(CURL * c)
{
}

static int responseCode = 200;

void test_set_response_code(int resp)
{
	responseCode = resp;
}

int curl_easy_getinfo(CURL * c, int type, void * data)
{
	if (type == CURLINFO_RESPONSE_CODE)
	{
		int* iData = (int*)data;
		*iData = responseCode;
		return CURLE_OK;
	}
	else
	{
		assert(false);
		return CURLE_SOME_MOCK_ERROR;
	}
}

int mosquitto_disconnect(struct mosquitto * mosq)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_kick_client_by_username(const char *username, bool with_will)
{
	return MOSQ_ERR_SUCCESS;
}

const char* mosquitto_client_username(struct mosquitto * mosq)
{
	return mosq->username;
}

int mosquitto_topic_matches_sub(const char * sub, const char * topic, bool * result)
{
	*result = true;
	return MOSQ_ERR_SUCCESS;
}

const char * mosquitto_client_id(const struct mosquitto * mosq)
{
	return "MOCK_ID";
}

int mosquitto_sub_topic_check(const char * topic)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_pub_topic_check(const char * topic)
{
	return MOSQ_ERR_SUCCESS;
}

const char* mosquitto_client_address(const struct mosquitto* client)
{
	return "MockedAddr";
}

int mosquitto_broker_publish_copy(
		const char *clientid,
		const char *topic,
		int payloadlen,
		const void *payload,
		int qos,
		bool retain,
		mosquitto_property *properties)
{
	authLog(LOG_PRIORITY_TRACE, "%s=%-.*s\n", topic, payloadlen, payload);
}
