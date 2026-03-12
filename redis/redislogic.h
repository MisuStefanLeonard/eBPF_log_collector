#ifndef __REDISLOGIC__
#define __REDISLOGIC__

#include <hiredis/hiredis.h>
#include <cjson/cJSON.h>
#include <string.h> // for strcmp

// Use redisContext (Sync) instead of redisAsyncContext
redisContext* connectToRedisServer(const char *host, int port);
void issueCommand(redisContext* c, const char* commandType, const char *key, const char *value);

#endif