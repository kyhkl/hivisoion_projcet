#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define ISspace(x) isspace((int)(x)) 
#define USERLEN 33
#define REALMLEN 64
#define QOPLEN   16
typedef struct httpauth_t{
    char username[USERLEN],password[USERLEN];
    char qop[QOPLEN],realm[QOPLEN],nc[QOPLEN];
    char cnonce[REALMLEN],response[REALMLEN],nonce[REALMLEN];
}httpauth_t;

void to_hex(char *in,int len,unsigned char *out);
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest);

int httpauth_set_auth(httpauth_t *auth,const char* username,const char* password,const char* realm,const char* nonce,const char* nc,const char* cnonce,const char* response,const char* qop);
int httpauth_get_response(httpauth_t *auth,char *cmd,char *url);
void request(int socket_fd,httpauth_t *auth,int flag);
int prase_response(char * response_buf ,httpauth_t *auth);


