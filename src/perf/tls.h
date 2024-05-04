#pragma once
#define TLS_CHIPER_DEFAULT "AES128-GCM-SHA256"

int tls_init(void);
void tls_exit(void);
void *tls_establish(int fd);
int tls_write(void *handle, const void *buf, int num);
int tls_read(void *handle, void *buf, int num);
const char *tls_chipher(const char *name = NULL);

