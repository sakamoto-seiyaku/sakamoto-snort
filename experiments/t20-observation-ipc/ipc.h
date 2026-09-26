#ifndef T20_IPC_H
#define T20_IPC_H
#include <stddef.h>
#include <stdint.h>
typedef struct ipc ipc;
typedef void (*record_fn)(const uint8_t *, size_t, void *);
ipc *ipc_open(const char *, int, uint64_t, int);
int ipc_write(ipc *, unsigned, const void *, size_t);
size_t ipc_read(ipc *, unsigned, size_t, record_fn, void *);
int ipc_wait(ipc *);
void ipc_notify(ipc *);
int ipc_done(ipc *);
void ipc_finish(ipc *);
void ipc_report(ipc *, const char *);
void ipc_close(ipc *);
uint64_t ipc_now(void);
uint64_t ipc_cpu(void);
#endif
