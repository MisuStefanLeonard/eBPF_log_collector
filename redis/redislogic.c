#include "redislogic.h"
#include <stdio.h>

/*
    ** Connect to redis (Synchronous)
*/
redisContext* connectToRedisServer(const char *host, int port) {
    // 1. Connect synchronously
    redisContext *c = redisConnect(host, port);

    // 2. Check for errors immediately
    if (c == NULL || c->err) {
        if (c) {
            printf("Connection Error: %s\n", c->errstr);
            redisFree(c);
        } else {
            printf("Connection Error: Can't allocate redis context\n");
        }
        return NULL;
    }

    printf("Connected to Redis at %s:%d\n", host, port);
    return c;
}

/*
    ** Issue a command
*/
void issueCommand(redisContext* c, const char* commandType, const char *key, const char *value) {
    if (c == NULL) return;

    redisReply *reply;

    // Use strcmp for string comparison!
    if (strcmp(commandType, "GET") == 0) {
        reply = redisCommand(c, "GET %s", key);
        if (reply->type == REDIS_REPLY_STRING) {
            printf("GET Result: %s\n", reply->str);
        }
        freeReplyObject(reply);
    } 
    else if (strcmp(commandType, "SET") == 0) {
        // Warning: 'value' must be a serialized string (JSON) here
        reply = redisCommand(c, "SET %s %s", key, value);
        freeReplyObject(reply);
    }
    // For Streams (What you likely want)
    else if (strcmp(commandType, "XADD") == 0) {
        reply = redisCommand(c, "XADD %s * data %s", key, value);
        freeReplyObject(reply);
    }
}