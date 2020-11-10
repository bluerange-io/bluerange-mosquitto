# Auth Plugin

## Overview
This is an auth plugin for the open source MQTT broker [Mosquitto](https://mosquitto.org/). On MQTT client logins, it calls a configured backend for validation and expects either an a JSON filled with all available ACL entries for that user on success, or an HTTP status reponse >= 300 if the access was denied. The returned ACL entries are then cached in a hash map for future use, thus omitting the requirement of repeatedly opening a connection to the backend.

## Building

Make is used to build the auth plugin. Mosquitto must be installed previously as a dependency. After that, just call

```
make
```

## Testing

Tests are build via CMake. While you are in the auth directory, execute the following to build the test project and execute it:

```
mkdir build
cd build
cmake ..
cmake --build . --target AuthTest
./AuthTest
```

## ACL syntax
The ACL payload consists of `aclEntries` and a `superuser` flag.
```
{
 "apiVersion": "1",
 "aclEntries": {
 "base/topic/#": "s",
 "base/topic/readonly/#": "rs"
 "base/topic/+/wildcard/#": "rws",
 },
 "superuser": false
}
```
The key of an `aclEntry` is a MQTT topic pattern matching the official syntax. + 
The value represents the permissions, where it can be a combination of the three characters `'r'` (read), `'w'` (write), `'s'` (subscribe).
In case the `superuser` flag is set to true, the client is allowed to read/write/subscribe to all topics and therefore the `aclEntries` can be ignored. Nevertheless the equivalent of "allow all" is the only entry:
```
{
 "apiVersion": "1",
 "aclEntries": {
 "#": "rws"
 },
 "superuser": true
}
```

## Broker Status
The special mosquitto topics starting with `$SYS`containing the broker status will be handled by the auth-plugin as exclusiv for superusers.

## Blacklist
The auth plugin blacklists user/password pairs for 10 seconds if the backend rejects the user. This is done to decrease the load on the backend in cases where users have old passwords and constantly try to connect.

## User hash table
Users are stored in a hash table. The amount of buckets in that table is constant for a compilation but can be changed by changing the AMOUNT_OF_HASH_BUCKETS define. Each bucket has a linked list of all users that have the same hash value. The hash is generated with djb2 (by Dan Bernstein), based on the username.

## Configuration

The auth plugin accepts the following arguments as configuration:

| Argument         | Description                                                                                                                   | Example                 |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| http_port        | The port of the backend                                                                                                       | 443                     |
| http_hostname    | The hostname of the backend                                                                                                   | backend.example.com     |
| http_getuser_uri | The URI that is called for ACL retrieval upon login.                                                                          | /mosquitto-auth/getuser |
| http_with_tls    | If https should be used instead of http                                                                                       | true                    |
| log_priority     | The lowest log priority that is still printed. Possible values: "FATAL", "ERROR", "WARNING", "INFO", "TRACE". Default: "INFO" | WARNING                 |
