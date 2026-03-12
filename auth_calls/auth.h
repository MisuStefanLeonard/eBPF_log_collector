#ifndef __AUTH_H__
#define __AUTH_H__

#include "../utils/utils.h"

typedef struct pam_handle_t{
    char *authtok;
    unsigned caller_is;
    void *pam_conversation;
    char *oldauthtok;
    char *prompt;                
    char *service_name; // command
    char *user; // user who logs in
    char *rhost; // remote host/ip
    char *ruser; // remote user name
    char *tty; // terminal or pty from where the user logs in
    char *xdisplay;
    char *authtok_type;

} pam_handle_t;

#endif