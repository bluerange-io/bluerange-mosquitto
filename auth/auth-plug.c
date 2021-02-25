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

/*
* LIMITATIONS:
*  1) No Multithreading support. According to the following link, this is currently
*     not required (but may be in the future): https://wiki.eclipse.org/Mosquitto/Multi-Thread
*/

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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cJSON.h"
#include "log.h"

#ifdef AUTH_TEST_ENABLED
time_t currentTime = 0;
void setTime(time_t time)
{
	currentTime = time;
}
#endif

time_t getTime()
{
#ifdef AUTH_TEST_ENABLED
	return currentTime;
#else
	return time(NULL);
#endif
}

typedef struct str_with_len
{
	char* str;
	size_t len;
	size_t capacity;
} str_with_len;

typedef struct User
{
	struct User *next;
	cJSON *acl_json;
	char *username;
	struct mosquitto *mosq;
	time_t last_usage_time;
} User;

typedef struct BlacklistEntry
{
	struct BlacklistEntry* next;
	char* username;
	char* password;
	time_t creation_time;
} BlacklistEntry;

#define AMOUNT_OF_HASH_BUCKETS (1024)
static User* hash_table_users[AMOUNT_OF_HASH_BUCKETS] = { 0 };
static char* url = NULL;
int amount_of_users = 0;

static BlacklistEntry* blacklist = NULL;

void clean_hash_table(int force, int panic);

size_t calculate_amount_of_hash_table_users()
{
	size_t ret_val = 0;
	size_t i = 0;
	for(i = 0; i<AMOUNT_OF_HASH_BUCKETS; i++)
	{
		User* current_user = hash_table_users[i];
		while(current_user)
		{
			ret_val++;
			current_user = current_user->next;
		}
	}
	return ret_val;
}

void* allocate_memory(size_t amount)
{
	void* ret_val = malloc(amount);
	if(!ret_val)
	{
		//We try to free up some memory.
		authLog(LOG_PRIORITY_WARNING, "No memory. Trying to clean up...");
		//This information might help us to find some memory leak.
		//Both numbers should be the same.
		authLog(LOG_PRIORITY_WARNING, "Calculated amount of Users: %d, tracked amount of Users: %d", (int)calculate_amount_of_hash_table_users(), amount_of_users);
		clean_hash_table(1, 0);
		ret_val = malloc(amount);
		if(!ret_val)
		{
			//As a last resort we try to free more memory in a more aggressive way.
			authLog(LOG_PRIORITY_ERROR, "No memory after clean. Cleaning aggressively...");
			clean_hash_table(1, 1);
			ret_val = malloc(amount);
			if(!ret_val)
			{
				//There isn't anything left we can do. Shutting down.
				authLog(LOG_PRIORITY_FATAL, "Out of memory!");
				exit(1); //Note: LOG_PRIORITY_FATAL already calls exit. This protects us agains behaviour changes.
			}
		}
	}
	return ret_val;
}

void remove_blacklist_head()
{
	if (!blacklist) return;
	BlacklistEntry* oldBlacklist = blacklist;
	blacklist = blacklist->next;
	free(oldBlacklist->username);
	free(oldBlacklist->password);
	free(oldBlacklist);
}

void remove_blacklist_entries_with_timeout()
{
	// The blacklist is always ordered from oldest to newest. This allows us to always
	// correctly assume that we are removing the first entry, if we remove anything.
	const time_t currTime = getTime();
	while (blacklist)
	{
		const time_t entryAliveFor = currTime - blacklist->creation_time;
		if (entryAliveFor > 10)
		{
			remove_blacklist_head();
		}
		else
		{
			return;
		}
	}
}

int is_user_blacklisted(const char* username, const char* password)
{
	remove_blacklist_entries_with_timeout();
	BlacklistEntry* iter = blacklist;
	while (iter)
	{
		if (   strcmp(username, iter->username) == 0
		    && strcmp(password, iter->password) == 0)
		{
			return 1;
		}
		iter = iter->next;
	}

	return 0;
}

void blacklist_user(const char* username, const char* password)
{
	const size_t usernameLength = strlen(username);
	const size_t passwordLength = strlen(password);

	char* usernameBuffer = allocate_memory(usernameLength + 1);
	char* passwordBuffer = allocate_memory(passwordLength + 1);

	strcpy(usernameBuffer, username);
	strcpy(passwordBuffer, password);

	BlacklistEntry* newEntry = allocate_memory(sizeof(BlacklistEntry));
	newEntry->creation_time = getTime();
	newEntry->next = NULL;
	newEntry->password = passwordBuffer;
	newEntry->username = usernameBuffer;

	if (blacklist == NULL)
	{
		blacklist = newEntry;
	}
	else
	{
		BlacklistEntry* iter = blacklist;
		while (iter->next)
		{
			iter = iter->next;
		}
		iter->next = newEntry;
	}
}

void clear_blacklist()
{
	while (blacklist)
	{
		remove_blacklist_head();
	}
}

User* get_last_entry(const size_t bucket)
{
	User* ret_val = hash_table_users[bucket];
	if(ret_val == NULL) return NULL;
	while(ret_val->next != NULL)
	{
		ret_val = ret_val->next;
	}
	return ret_val;
}

size_t generate_hash_for_username(const char* username)
{
	//djb2 hash by Dan Bernstein
	unsigned long hash = 5381;
	int c = 0;
	
	while ((c = *username++))
	{
		hash = ((hash << 5) + hash) + c;
	}
	
	return hash;
}

void store_user_in_hash_table(User* user)
{
	const size_t hash = generate_hash_for_username(user->username);
	const size_t bucket = hash % AMOUNT_OF_HASH_BUCKETS;
	User* previous_user = get_last_entry(bucket);
	if(previous_user == NULL)
	{
		hash_table_users[bucket] = user;
	}
	else
	{
		previous_user->next = user;
	}	
}

User* create_user(cJSON *acl_json, const char* const username, struct mosquitto *mosq)
{
	clean_hash_table(0, 0);
	
	const size_t username_len = strlen(username);
	if(username_len > 16 * 1024)
	{
		//Pure sanity check.
		authLog(LOG_PRIORITY_WARNING, "Received username that exceeded the char limit of 16*1024");
		return NULL;
	}
	
	User* user = allocate_memory(sizeof(User));
	memset(user, 0, sizeof(User));
	user->next = NULL;
	user->acl_json = acl_json;
	user->username = allocate_memory(username_len + 1);
	user->username[0] = '\0';
	strcpy(user->username, username);
	user->last_usage_time = getTime();
	user->mosq = mosq;
	
	store_user_in_hash_table(user);
	amount_of_users++;
	
	return user;
}

User* get_user(const char* const username, User** out_previous_user)
{
	const size_t hash = generate_hash_for_username(username);
	const size_t bucket = hash % AMOUNT_OF_HASH_BUCKETS;
	
	User* current_user = hash_table_users[bucket];
	if(out_previous_user) *out_previous_user = NULL;
	if(current_user == NULL) return NULL;
	while(1)
	{
		if(strcmp(username, current_user->username) == 0)
		{
			return current_user;
		}
		if(current_user->next == NULL) return NULL;
		if(out_previous_user) *out_previous_user = current_user;
		current_user = current_user->next;
	}
}

void destroy_user(User* user, User* previous_user)
{
	if(previous_user)
	{
		//We are NOT the start of the list.
		previous_user->next = user->next;
	}
	else
	{
		//We ARE the start of the list
		const size_t hash = generate_hash_for_username(user->username);
		const size_t bucket = hash % AMOUNT_OF_HASH_BUCKETS;
		hash_table_users[bucket] = user->next;
	}
	authLog(LOG_PRIORITY_TRACE, "Destroying user: %s", user->username ? user->username : "NULL");
	cJSON_Delete(user->acl_json);
	free(user->username);
	free(user);
	amount_of_users--;
}

void clean_hash_table(int force, int panic)
{
	static int calls = 0;
	size_t i = 0;
	calls++;
	//We don't want to clean the hash table on every single usage.
	if(calls >= 1024 || force)
	{
		calls = 0;
		
		const size_t calculated_amount_of_users = calculate_amount_of_hash_table_users();
		if(calculated_amount_of_users != amount_of_users)
		{
			//Poor mans leak detection that might be useful.
			//These two values should be the same! If they are not it means that some users got lost somehow (memory leak? wrong linked list update?).
			authLog(LOG_PRIORITY_WARNING, "Possible leak detected. Calculated: %d, tracked: %d", (int)calculated_amount_of_users, amount_of_users);
		}
		
		const time_t now = getTime();
		
		for(i = 0; i<AMOUNT_OF_HASH_BUCKETS; i++)
		{
			User* curr_user = hash_table_users[i];
			User* prev_user = NULL;
			while(curr_user != NULL)
			{
				User* next_user = curr_user->next;
				
				const time_t kill_time = panic ? (60 * 60 /* 1 hour */) : (60 * 60 * 24 /* 24 hours */);
				const time_t time_diff = now - curr_user->last_usage_time;
				if(time_diff > kill_time)
				{
					mosquitto_kick_client_by_username(curr_user->username, false);
					destroy_user(curr_user, prev_user);
				}
				else
				{
					prev_user = curr_user;
				}
				curr_user = next_user;
			}
		}
	}
}

void destroy_user_if_exists(const char* const username)
{
	User* previous_user = NULL;
	User* existingUser = get_user(username, &previous_user);
	if(existingUser != NULL)
	{
		destroy_user(existingUser, previous_user);
	}
}

char* cutOffToken(char* tokenString)
{
	while (*tokenString)
	{
		if (*tokenString == '/')
		{
			*tokenString = '\0';
			return tokenString + 1;
		}
		tokenString++;
	}
	return NULL;
}

bool matchSubTopic(const char* subscription, const char* topic)
{
	const size_t subLen = strlen(subscription);
	const size_t topicLen = strlen(topic);

	if (subLen == 0 || topicLen == 0)
	{
		return false;
	}

	if (subscription[0] != '$' && topic[0] == '$')
	{
		return false;
	}

	char* const subTokensChunk = allocate_memory(subLen + 1);
	char* const topicTokensChunk = allocate_memory(topicLen + 1);

	char* subTokens = subTokensChunk;
	char* topicTokens = topicTokensChunk;

	strcpy(subTokensChunk, subscription);
	strcpy(topicTokensChunk, topic);

	bool retVal = false;

	while (subTokens != NULL && topicTokens != NULL)
	{
		char* subCurrentToken = subTokens;
		char* topicCurrentToken = topicTokens;
		subTokens = cutOffToken(subTokens);
		topicTokens = cutOffToken(topicTokens);

		if (strcmp(subCurrentToken, "#") == 0)
		{
			retVal = true;
			goto end;
		}

		if (strcmp(subCurrentToken, "+") == 0 || strcmp(subCurrentToken, topicCurrentToken) == 0)
		{
			continue;
		}

		retVal = false;
		goto end;
	}

	if (subTokens == NULL)
	{
		if (topicTokens == NULL)
		{
			retVal = true;
			goto end;
		}
		else
		{
			retVal = false;
			goto end;
		}
	}

	if (topicTokens == NULL)
	{
		retVal = false;
		goto end;
	}

end:
	free(subTokensChunk);
	free(topicTokensChunk);
	return retVal;
}

int mosquitto_auth_plugin_version(void)
{
	return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *auth_opts, int auth_opt_count)
{
	int i = 0;
	struct mosquitto_opt *o = NULL;
	char* hostname = NULL;
	char* get_user_uri = NULL;
	int port = 443;
	int useTLS = 0;
	setAuthLogPriority(LOG_PRIORITY_INFO);
	
	*user_data = NULL; // We don't use user_data.
	authLog(LOG_PRIORITY_TRACE, "auth-init");
	
	for (i = 0, o = auth_opts; i < auth_opt_count; i++, o++) {
		const char* key = o->key;
		const char* value = o->value;
		if(strcmp(key, "http_port") == 0)
		{
			port = atoi(value);
		}
		else if(strcmp(key, "http_hostname") == 0)
		{
			size_t len = strlen(value);
			hostname = allocate_memory(len + 1);
			hostname[0] = '\0';
			strcpy(hostname, value);
		}
		else if(strcmp(key, "http_getuser_uri") == 0)
		{
			size_t len = strlen(value);
			get_user_uri = allocate_memory(len + 1);
			get_user_uri[0] = '\0';
			strcpy(get_user_uri, value);
		}
		else if(strcmp(key, "http_with_tls") == 0)
		{
			if(strcmp(value, "false") == 0)
			{
				useTLS = 0;
			}
			else if(strcmp(value, "true") == 0)
			{
				useTLS = 1;
			}
			else
			{
				authLog(LOG_PRIORITY_FATAL, "Unexpected value for http_with_tls. Only the exact strings \"false\" and \"true\" are supported, but was %s", value);
			}
		}
		else if (strcmp(key, "log_priority") == 0)
		{
			if (strcmp(value, "FATAL") == 0)
			{
				setAuthLogPriority(LOG_PRIORITY_FATAL);
			}
			else if (strcmp(value, "ERROR") == 0)
			{
				setAuthLogPriority(LOG_PRIORITY_ERROR);
			}
			else if (strcmp(value, "WARNING") == 0)
			{
				setAuthLogPriority(LOG_PRIORITY_WARNING);
			}
			else if (strcmp(value, "INFO") == 0)
			{
				setAuthLogPriority(LOG_PRIORITY_INFO);
			}
			else if (strcmp(value, "TRACE") == 0)
			{
				setAuthLogPriority(LOG_PRIORITY_TRACE);
			}
			else
			{
				authLog(LOG_PRIORITY_FATAL, "Unexpected value for log_prio. Only the exact strings \"FATAL\", \"ERROR\", \"WARNING\", \"INFO\", and \"TRACE\" are supported, but was %s", value);
			}
		}
		else
		{
			authLog(LOG_PRIORITY_WARNING, "Unrecognized config parameter. [%s]: %s", key ? key : "NULL", value ? value : "NULL");
		}
	}
	
	int ret_val = MOSQ_ERR_UNKNOWN;
	if(port != 0 && hostname != NULL && get_user_uri != NULL)
	{	
		size_t urllen = strlen(hostname) + strlen(get_user_uri) + 20;
		url = (char *)allocate_memory(urllen);
		
		snprintf(url, urllen, "%s://%s:%d%s",
			(useTLS ? "https" : "http"),
			hostname,
			port,
			get_user_uri);
		authLog(LOG_PRIORITY_INFO, "Initialized with URL: %s", url);
		ret_val = MOSQ_ERR_SUCCESS;
	}
	
	free(hostname);
	free(get_user_uri);
	return ret_val;
}

int mosquitto_auth_plugin_cleanup(void* user_data, struct mosquitto_opt* auth_opts, int opt_count)
{
	authLog(LOG_PRIORITY_INFO, "Auth Plugin is shutting down.");
	size_t i = 0;
	free(url);
	
	for(i = 0; i<AMOUNT_OF_HASH_BUCKETS; i++)
	{
		while(hash_table_users[i])
		{
			destroy_user(hash_table_users[i], NULL);
		}
	}

	memset(hash_table_users, 0, sizeof(hash_table_users));
	url = NULL;
	amount_of_users = 0;

	clear_blacklist();
	
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void* user_data, struct mosquitto_opt* auth_opts, int opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void* user_data, struct mosquitto_opt* auth_opts, int opt_count, bool reload)
{
	return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void* user_data, int access, struct mosquitto* client, const struct mosquitto_acl_msg* msg)
{
	const char* username = mosquitto_client_username(client);
	if(!username)
	{
		authLog(LOG_PRIORITY_WARNING, "username was NULL!");
		return MOSQ_ERR_UNKNOWN;
	}
	User* user = get_user(username, NULL);
	if(!user)
	{
		authLog(LOG_PRIORITY_WARNING, "Could not find user: %s", username);
		return MOSQ_ERR_UNKNOWN;
	}
	user->last_usage_time = getTime();
	
	char rws_access;
	if     (access == MOSQ_ACL_READ     ) rws_access = 'r';
	else if(access == MOSQ_ACL_WRITE    ) rws_access = 'w';
	else if(access == MOSQ_ACL_SUBSCRIBE) rws_access = 's';
	else return MOSQ_ERR_UNKNOWN;
	
	if(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(user->acl_json, "superuser")))
	{
		//Super Users have access to everything.
		return MOSQ_ERR_SUCCESS;
	}
	
	const char* topic = msg->topic;
	if(!topic)
	{
		authLog(LOG_PRIORITY_WARNING, "topic was NULL!");
		return MOSQ_ERR_UNKNOWN;
	}

	if (rws_access == 's' && mosquitto_sub_topic_check(topic) != MOSQ_ERR_SUCCESS)
	{
		authLog(LOG_PRIORITY_WARNING, "Subscription did not pass topic check. Topic: %s", topic);
		return MOSQ_ERR_UNKNOWN;
	}

	if ((rws_access == 'r' || rws_access == 'w') && mosquitto_pub_topic_check(topic) != MOSQ_ERR_SUCCESS)
	{
		authLog(LOG_PRIORITY_WARNING, "Read/Write did not pass topic check. Topic: %s", topic);
		return MOSQ_ERR_UNKNOWN;
	}

	cJSON* aclEntries = cJSON_GetObjectItemCaseSensitive(user->acl_json, "aclEntries");
	cJSON* current_element = NULL;
	cJSON_ArrayForEach(current_element, aclEntries)
	{
		const char* sub = current_element->string;
		const char* rws = current_element->valuestring;
		//Check that this ACL entry has the same access type.
		if (strchr(rws, rws_access))
		{
			//Check that the ACL entry is valid.
			if (mosquitto_sub_topic_check(sub) == MOSQ_ERR_SUCCESS)
			{
				if (matchSubTopic(sub, topic))
				{
					return MOSQ_ERR_SUCCESS;
				}
			}
			else
			{
				authLog(LOG_PRIORITY_ERROR, "ACL Entry was malformed. Sub: %s, user: %s", sub, username);
				// We continue iterating as other ACL Entries might be correct.
			}
		}
	}
	authLog(LOG_PRIORITY_INFO, "Not allowed. Topic: %s rws: %c user: %s", topic, rws_access, username);
	return MOSQ_ERR_ACL_DENIED;
}

size_t curl_callback_write(void *contents, size_t size, size_t nmemb, str_with_len *buffer)
{
	if(!buffer) return 0;
	if(!contents) return 0;
	const size_t actual_size = size * nmemb;
	const size_t new_length = actual_size + buffer->len;
	if(new_length > 1024 * 1024 * 1024 /*1 GB*/)
	{
		//sanity check. ACL lists probably won't be longer than 1 giga byte.
		authLog(LOG_PRIORITY_WARNING, "Received file that exceeded the 1 GB limit.");
		return 0;
	}
	const size_t new_needed_capacity = new_length + 1;
	if(new_needed_capacity >= buffer->capacity)
	{
		size_t new_capacity = buffer->capacity * 2;
		if(new_needed_capacity >= new_capacity) new_capacity = new_needed_capacity;
		
		char* new_buffer = allocate_memory(new_capacity);
		memcpy(new_buffer, buffer->str, buffer->len);
		char* old_buffer = buffer->str;
		buffer->str = new_buffer;
		buffer->capacity = new_capacity;
		free(old_buffer);
	}
	
	//Careful, contents is NOT zero terminated! strcpy is not an option!
	memcpy(buffer->str + buffer->len, contents, actual_size);
	buffer->len = new_length;
	buffer->str[new_length] = '\0';
	
	return actual_size;
}

int mosquitto_auth_unpwd_check(void *userdata, struct mosquitto *client, const char *username, const char *password)
{
	//Variables that need to be deleted/freed/...
	//Must be defined and set at the top to avoid
	//passing dangling/incorrect pointers to
	//clean functions.
	char* data = NULL;
	char* payload_buffer = NULL;
	CURL *curl = NULL;
	cJSON *json = NULL;

	if(!username || !(*username) || !password || !(*password))
	{
		authLog(LOG_PRIORITY_WARNING, "Corrupt username or password");
		return MOSQ_ERR_AUTH;
	}

	if (is_user_blacklisted(username, password))
	{
		authLog(LOG_PRIORITY_TRACE, "Blacklisted user tried to login: %s", username);
		return MOSQ_ERR_AUTH;
	}
	
	int ret_val = MOSQ_ERR_SUCCESS;
	
	curl = curl_easy_init();
	if(!curl)
	{
		authLog(LOG_PRIORITY_WARNING, "Failed to initialize curl");
		goto err;
	}
	
	const char *clientid = mosquitto_client_id(client);
	if(!clientid)
	{
		authLog(LOG_PRIORITY_WARNING, "Mosquitto did not return a valid clientid");
		goto err;
	}
	
	const char* escaped_username = curl_easy_escape(curl, username, 0);
	const char* escaped_password = curl_easy_escape(curl, password, 0);
	const char* escaped_clientid = curl_easy_escape(curl, clientid, 0);
	if(!escaped_password || !escaped_password || !escaped_clientid)
	{
		authLog(LOG_PRIORITY_WARNING, "Curl failed to escape username(%s : %s), password(? : ?) or clientid(%s : %s).",
			username ? username : "NULL", escaped_username ? escaped_username : "NULL",
			//password ? password : "NULL", escaped_password ? escaped_password : "NULL", // Not logging password for security reasons (unknown who has access to the logs).
			clientid ? clientid : "NULL", escaped_clientid ? escaped_clientid : "NULL");
		goto err;
	}
	
	const char* const data_placeholder = "username=%s&password=%s&clientid=%s";
	
	data = (char *)allocate_memory(strlen(escaped_username) + strlen(escaped_password) + strlen(escaped_clientid) + strlen(data_placeholder) + 1);
	sprintf(data, data_placeholder,
		escaped_username,
		escaped_password,
		escaped_clientid);
	
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	
	str_with_len curl_buffer;
#define DEFAULT_SIZE (10)
	curl_buffer.str = allocate_memory(DEFAULT_SIZE);
	curl_buffer.str[0] = '\0';
	curl_buffer.len = 0;
	curl_buffer.capacity = DEFAULT_SIZE;
#undef DEFAULT_SIZE
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &curl_buffer);
	
	int re = curl_easy_perform(curl);
	int respCode = 0;
	payload_buffer = curl_buffer.str;
	if (re == CURLE_OK) {
		memset(&curl_buffer, 0, sizeof(curl_buffer));
		re = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &respCode);
		if (re == CURLE_OK && respCode >= 200 && respCode < 300) {
			json = cJSON_Parse(payload_buffer);
			
			if(!json)
			{
				authLog(LOG_PRIORITY_WARNING, "Failed to parse json! %s", payload_buffer);
				goto err;
			}
			cJSON* aclEntries = cJSON_GetObjectItemCaseSensitive(json, "aclEntries");
			cJSON* superUserEntry = cJSON_GetObjectItemCaseSensitive(json, "superuser");
			if(!aclEntries || !superUserEntry)
			{
				authLog(LOG_PRIORITY_WARNING, "JSON had no aclEntries or superUserEntry %s", payload_buffer);
				goto err;
			}
			
			destroy_user_if_exists(username);
			
			User* user = create_user(json, username, client);
			if(!user)
			{
				goto err;
			}
			
			authLog(LOG_PRIORITY_TRACE, "User logged in: %s", username);
			if (getAuthLogPriority() <= LOG_PRIORITY_TRACE)
			{
				char* jsonLog = cJSON_Print(json);
				authLog(LOG_PRIORITY_TRACE, "%s", jsonLog ? jsonLog : "Could not load JSON");
				free(jsonLog);
			}
			goto end;
		} else {
			const char* clientAddr = mosquitto_client_address(client);
			if (!clientAddr) clientAddr = "Could not get addr";
			authLog(LOG_PRIORITY_WARNING, "Curl: %d, RespCode: %d, username %s, clientid %s, addr %s", re, respCode, username, clientid, clientAddr);
			blacklist_user(username, password);
			ret_val = MOSQ_ERR_AUTH;
			goto err;
		}
	} else {
		authLog(LOG_PRIORITY_WARNING, "Curl was unable to perform with reason: %d", re);
		goto err;
	}
err:
	if(ret_val == MOSQ_ERR_SUCCESS) ret_val = MOSQ_ERR_UNKNOWN;
	cJSON_Delete(json);
end:
	free(payload_buffer);
	free(data);
	curl_easy_cleanup(curl);
	return ret_val;
}

#ifdef AUTH_TEST_ENABLED
void* bootMock()
{
	setTime(0);
	test_set_response_code(200);
	void* userData = NULL;
	struct mosquitto_opt opt[] = {
		{
			"http_port",
			"123"
		},
		{
			"http_hostname",
			"mock_hostname"
		},
		{
			"http_getuser_uri",
			"mock_getuser_uri"
		},
		{
			"http_with_tls",
			"true"
		},
		{
			"log_priority",
			"TRACE"
		}
	};
	assert(mosquitto_auth_plugin_version() == MOSQ_AUTH_PLUGIN_VERSION);
	assert(mosquitto_auth_plugin_init(&userData, opt, sizeof(opt) / sizeof(opt[0])) == MOSQ_ERR_SUCCESS);
	assert(mosquitto_auth_security_init(&userData, NULL, 0, false) == MOSQ_ERR_SUCCESS);
	return userData;
}

void shutdownMock(void* userData)
{
	assert(mosquitto_auth_security_cleanup(&userData, NULL, 0, false) == MOSQ_ERR_SUCCESS);
	assert(mosquitto_auth_plugin_cleanup(&userData, NULL, 0) == MOSQ_ERR_SUCCESS);
}

void testACL()
{
	void* userData = bootMock();

	const char* username = "MOCK_USER";
	const char* password = "MOCK_PW";
	struct mosquitto mosq;
	memset(&mosq, 0, sizeof(mosq));
	mosq.username = username;
	mosq.password = password;
	assert(mosquitto_auth_unpwd_check(&userData, &mosq, username, password) == MOSQ_ERR_SUCCESS);

	struct mosquitto_acl_msg msg;
	memset(&msg, 0, sizeof(msg));
	msg.topic = "MyTopicThatIsNotAllowed";
	assert(mosquitto_auth_acl_check(&userData, MOSQ_ACL_READ, &mosq, &msg) == MOSQ_ERR_ACL_DENIED);
	msg.topic = "rltn-iot/2A922016-2AB5-45CB-8A8F-E2CF7BE614A8/";
	assert(mosquitto_auth_acl_check(&userData, MOSQ_ACL_READ, &mosq, &msg) == MOSQ_ERR_SUCCESS);

	shutdownMock(userData);
}

int newMockUser(void* userData, const char* username, const char* password)
{
	struct mosquitto mosq;
	memset(&mosq, 0, sizeof(mosq));
	mosq.username = username;
	mosq.password = password;
	return mosquitto_auth_unpwd_check(&userData, &mosq, username, password);
}

void userTest(size_t amount)
{
	void* userData = bootMock();

	for (int i = 0; i < amount; i++)
	{
		//New user every 5 minutes.
		setTime(i * (60 * 5));
		char username[128];
		snprintf(username, sizeof(username), "MOCK_USER%d", i);
		const char* password = "MOCK_PW";
		assert(newMockUser(userData, username, password) == MOSQ_ERR_SUCCESS);
	}

	shutdownMock(userData);
}

void testLotsOfUsers()
{
	userTest(AMOUNT_OF_HASH_BUCKETS * 10);
}

void testFewUsers()
{
	userTest(AMOUNT_OF_HASH_BUCKETS / 2);
}

void testBlacklist()
{
	void* userData = bootMock();

	//First we test that a user can login
	assert(newMockUser(userData, "user", "pw") == MOSQ_ERR_SUCCESS);

	//Next we decline a user
	test_set_response_code(401);
	assert(newMockUser(userData, "inval", "pw") == MOSQ_ERR_AUTH);

	//The user is now blacklisted and should return the same...
	assert(newMockUser(userData, "inval", "pw") == MOSQ_ERR_AUTH);

	//... even if we would return success by the backend (because the user is now blacklisted)
	test_set_response_code(200);
	assert(newMockUser(userData, "inval", "pw") == MOSQ_ERR_AUTH);

	//Other users however can still login
	assert(newMockUser(userData, "happy", "pw") == MOSQ_ERR_SUCCESS);

	//The user is blacklisted for 9 more seconds
	for (time_t i = 0; i <= 10; i++)
	{
		setTime(i);
		assert(newMockUser(userData, "inval", "pw") == MOSQ_ERR_AUTH);
	}

	//After 10 seconds the user is free to login again.
	setTime(11);
	assert(newMockUser(userData, "inval", "pw") == MOSQ_ERR_SUCCESS);

	//Next we test it with multiple blacklisted users
	for (int i = 0; i < 5; i++)
	{
		setTime(100 + i);
		char username[128];
		snprintf(username, sizeof(username), "MOCK_USER%d", i);
		test_set_response_code(401);
		assert(newMockUser(userData, username, "MOCK_PW") == MOSQ_ERR_AUTH);
		snprintf(username, sizeof(username), "MOCK_HAPPY_USER%d", i);
		test_set_response_code(200);
		assert(newMockUser(userData, username, "MOCK_PW") == MOSQ_ERR_SUCCESS);
	}

	//All of them are still blacklisted after 5 seconds.
	test_set_response_code(200);
	for (int i = 0; i < 5; i++)
	{
		setTime(105 + i);
		char username[128];
		snprintf(username, sizeof(username), "MOCK_USER%d", i);
		assert(newMockUser(userData, username, "MOCK_PW") == MOSQ_ERR_AUTH);
		snprintf(username, sizeof(username), "MOCK_HAPPY_USERRRR%d", i);
		assert(newMockUser(userData, username, "MOCK_PW") == MOSQ_ERR_SUCCESS);
	}

	//But are free to login after 10.
	test_set_response_code(200);
	for (int i = 0; i < 5; i++)
	{
		setTime(111 + i);
		char username[128];
		snprintf(username, sizeof(username), "MOCK_USER%d", i);
		assert(newMockUser(userData, username, "MOCK_PW") == MOSQ_ERR_SUCCESS);
		snprintf(username, sizeof(username), "MOCK_HAPPY_USERRRRRRRRR%d", i);
		assert(newMockUser(userData, username, "MOCK_PW") == MOSQ_ERR_SUCCESS);
	}


	//We block one last user so that the sanitizers check for correct cleanup.
	test_set_response_code(401);
	assert(newMockUser(userData, "VeryUnhappyUser", ":(") == MOSQ_ERR_AUTH);

	shutdownMock(userData);
}

void testMatcher()
{
	assert(true  == matchSubTopic("iot/abc/#", "iot/abc/hallo"));
	assert(false == matchSubTopic("iot/abc/def/#", "iot/abc/hallo"));
	assert(true  == matchSubTopic("iot/abc/#", "iot/abc/#"));
	assert(true  == matchSubTopic("iot/+/#", "iot/def/#"));
	assert(false == matchSubTopic("iot/abc/#", "iot/+/#"));
	assert(true  == matchSubTopic("iot/+/#", "iot/+/#"));
	assert(true  == matchSubTopic("iot/abc/#", "iot/abc/hallo"));
	assert(true  == matchSubTopic("#", "iot/abc/hallo"));
	assert(false == matchSubTopic("", "iot/abc/hallo"));
	assert(false == matchSubTopic("iot/abc/hallo/#", ""));
	assert(false == matchSubTopic("", ""));
	assert(true  == matchSubTopic("iot/+/abc", "iot//abc"));
	assert(true  == matchSubTopic("iot//abc", "iot//abc"));
	assert(false == matchSubTopic("iot//abc", "iot/+/abc"));
	assert(false == matchSubTopic("iot/abc/#", "iot/abc"));
	assert(true  == matchSubTopic("iot/abc/#", "iot/abc/"));
	assert(true  == matchSubTopic("iot", "iot"));
	assert(false == matchSubTopic("iot/+", "iot"));
	assert(true  == matchSubTopic("iot/+", "iot/"));
	assert(true  == matchSubTopic("iot/+", "iot/abc"));
	assert(false == matchSubTopic("iot/+", "iot//"));
	assert(false == matchSubTopic("iot/+/#", "iot/abc"));
	assert(true  == matchSubTopic("iot/+/#", "iot/abc/hallo"));
	assert(false == matchSubTopic("#", "$SYS/a"));
	assert(false == matchSubTopic("#", "$SYS/#"));
}

int main()
{
	testMatcher();
	testACL();
	testBlacklist();
	testFewUsers();
	testLotsOfUsers();
}
#endif
