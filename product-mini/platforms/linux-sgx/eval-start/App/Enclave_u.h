#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "stdint.h"
#include "stdbool.h"
#include "unistd.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
#define PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wait_timeout_ocall, (unsigned long long waiter, unsigned long long timeout));
#endif
#ifndef PTHREAD_CREATE_OCALL_DEFINED__
#define PTHREAD_CREATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_create_ocall, (unsigned long long self));
#endif
#ifndef PTHREAD_WAKEUP_OCALL_DEFINED__
#define PTHREAD_WAKEUP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wakeup_ocall, (unsigned long long waiter));
#endif
#ifndef OCALL_OPEN_DEFINED__
#define OCALL_OPEN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open, (const char* pathname, int flags, bool has_mode, unsigned int mode));
#endif
#ifndef OCALL_OPENAT_DEFINED__
#define OCALL_OPENAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_openat, (int dirfd, const char* pathname, int flags, bool has_mode, unsigned int mode));
#endif
#ifndef OCALL_CLOSE_DEFINED__
#define OCALL_CLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int fd));
#endif
#ifndef OCALL_READ_DEFINED__
#define OCALL_READ_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read, (int fd, void* buf, size_t read_size));
#endif
#ifndef OCALL_LSEEK_DEFINED__
#define OCALL_LSEEK_DEFINED__
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lseek, (int fd, off_t offset, int whence));
#endif
#ifndef OCALL_FTRUNCATE_DEFINED__
#define OCALL_FTRUNCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftruncate, (int fd, off_t length));
#endif
#ifndef OCALL_FSYNC_DEFINED__
#define OCALL_FSYNC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fsync, (int fd));
#endif
#ifndef OCALL_FDATASYNC_DEFINED__
#define OCALL_FDATASYNC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fdatasync, (int fd));
#endif
#ifndef OCALL_ISATTY_DEFINED__
#define OCALL_ISATTY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_isatty, (int fd));
#endif
#ifndef OCALL_FDOPENDIR_DEFINED__
#define OCALL_FDOPENDIR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fdopendir, (int fd, void** p_dirp));
#endif
#ifndef OCALL_READDIR_DEFINED__
#define OCALL_READDIR_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readdir, (void* dirp));
#endif
#ifndef OCALL_REWINDDIR_DEFINED__
#define OCALL_REWINDDIR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_rewinddir, (void* dirp));
#endif
#ifndef OCALL_SEEKDIR_DEFINED__
#define OCALL_SEEKDIR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_seekdir, (void* dirp, long int loc));
#endif
#ifndef OCALL_TELLDIR_DEFINED__
#define OCALL_TELLDIR_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_telldir, (void* dirp));
#endif
#ifndef OCALL_CLOSEDIR_DEFINED__
#define OCALL_CLOSEDIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_closedir, (void* dirp));
#endif
#ifndef OCALL_STAT_DEFINED__
#define OCALL_STAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_stat, (const char* pathname, void* buf, unsigned int buf_len));
#endif
#ifndef OCALL_FSTAT_DEFINED__
#define OCALL_FSTAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fstat, (int fd, void* buf, unsigned int buf_len));
#endif
#ifndef OCALL_FSTATAT_DEFINED__
#define OCALL_FSTATAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fstatat, (int dirfd, const char* pathname, void* buf, unsigned int buf_len, int flags));
#endif
#ifndef OCALL_MKDIRAT_DEFINED__
#define OCALL_MKDIRAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_mkdirat, (int dirfd, const char* pathname, unsigned int mode));
#endif
#ifndef OCALL_LINK_DEFINED__
#define OCALL_LINK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_link, (const char* oldpath, const char* newpath));
#endif
#ifndef OCALL_LINKAT_DEFINED__
#define OCALL_LINKAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_linkat, (int olddirfd, const char* oldpath, int newdirfd, const char* newpath, int flags));
#endif
#ifndef OCALL_UNLINKAT_DEFINED__
#define OCALL_UNLINKAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_unlinkat, (int dirfd, const char* pathname, int flags));
#endif
#ifndef OCALL_READLINK_DEFINED__
#define OCALL_READLINK_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readlink, (const char* pathname, char* buf, size_t bufsiz));
#endif
#ifndef OCALL_READLINKAT_DEFINED__
#define OCALL_READLINKAT_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readlinkat, (int dirfd, const char* pathname, char* buf, size_t bufsiz));
#endif
#ifndef OCALL_RENAMEAT_DEFINED__
#define OCALL_RENAMEAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_renameat, (int olddirfd, const char* oldpath, int newdirfd, const char* newpath));
#endif
#ifndef OCALL_SYMLINKAT_DEFINED__
#define OCALL_SYMLINKAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_symlinkat, (const char* target, int newdirfd, const char* linkpath));
#endif
#ifndef OCALL_IOCTL_DEFINED__
#define OCALL_IOCTL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ioctl, (int fd, unsigned long int request, void* arg, unsigned int arg_len));
#endif
#ifndef OCALL_FCNTL_DEFINED__
#define OCALL_FCNTL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl, (int fd, int cmd));
#endif
#ifndef OCALL_FCNTL_LONG_DEFINED__
#define OCALL_FCNTL_LONG_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl_long, (int fd, int cmd, long int arg));
#endif
#ifndef OCALL_REALPATH_DEFINED__
#define OCALL_REALPATH_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_realpath, (const char* path, char* buf, unsigned int buf_len));
#endif
#ifndef OCALL_POSIX_FALLOCATE_DEFINED__
#define OCALL_POSIX_FALLOCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_posix_fallocate, (int fd, off_t offset, off_t len));
#endif
#ifndef OCALL_POLL_DEFINED__
#define OCALL_POLL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_poll, (void* fds, unsigned int nfds, int timeout, unsigned int fds_len));
#endif
#ifndef OCALL_GETOPT_DEFINED__
#define OCALL_GETOPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getopt, (int argc, char* argv_buf, unsigned int argv_buf_len, const char* optstring));
#endif
#ifndef OCALL_READV_DEFINED__
#define OCALL_READV_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_readv, (int fd, char* iov_buf, unsigned int buf_size, int iovcnt, bool has_offset, off_t offset));
#endif
#ifndef OCALL_WRITEV_DEFINED__
#define OCALL_WRITEV_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_writev, (int fd, char* iov_buf, unsigned int buf_size, int iovcnt, bool has_offset, off_t offset));
#endif
#ifndef OCALL_CLOCK_GETTIME_DEFINED__
#define OCALL_CLOCK_GETTIME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clock_gettime, (unsigned int clock_id, void* tp_buf, unsigned int tp_buf_size));
#endif
#ifndef OCALL_CLOCK_GETRES_DEFINED__
#define OCALL_CLOCK_GETRES_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clock_getres, (int clock_id, void* res_buf, unsigned int res_buf_size));
#endif
#ifndef OCALL_UTIMENSAT_DEFINED__
#define OCALL_UTIMENSAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_utimensat, (int dirfd, const char* pathname, const void* times_buf, unsigned int times_buf_size, int flags));
#endif
#ifndef OCALL_FUTIMENS_DEFINED__
#define OCALL_FUTIMENS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_futimens, (int fd, const void* times_buf, unsigned int times_buf_size));
#endif
#ifndef OCALL_CLOCK_NANOSLEEP_DEFINED__
#define OCALL_CLOCK_NANOSLEEP_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_clock_nanosleep, (unsigned int clock_id, int flags, const void* req_buf, unsigned int req_buf_size, void* rem_buf, unsigned int rem_buf_size));
#endif
#ifndef OCALL_RAISE_DEFINED__
#define OCALL_RAISE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_raise, (int sig));
#endif
#ifndef OCALL_SCHED_YIELD_DEFINED__
#define OCALL_SCHED_YIELD_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sched_yield, (void));
#endif
#ifndef OCALL_PTHREAD_RWLOCK_INIT_DEFINED__
#define OCALL_PTHREAD_RWLOCK_INIT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_rwlock_init, (void** rwlock, void* attr));
#endif
#ifndef OCALL_PTHREAD_RWLOCK_DESTROY_DEFINED__
#define OCALL_PTHREAD_RWLOCK_DESTROY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_rwlock_destroy, (void* rwlock));
#endif
#ifndef OCALL_PTHREAD_RWLOCK_RDLOCK_DEFINED__
#define OCALL_PTHREAD_RWLOCK_RDLOCK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_rwlock_rdlock, (void* rwlock));
#endif
#ifndef OCALL_PTHREAD_RWLOCK_WRLOCK_DEFINED__
#define OCALL_PTHREAD_RWLOCK_WRLOCK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_rwlock_wrlock, (void* rwlock));
#endif
#ifndef OCALL_PTHREAD_RWLOCK_UNLOCK_DEFINED__
#define OCALL_PTHREAD_RWLOCK_UNLOCK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_pthread_rwlock_unlock, (void* rwlock));
#endif
#ifndef OCALL_GET_ERRNO_DEFINED__
#define OCALL_GET_ERRNO_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_errno, (void));
#endif
#ifndef OCALL_ACCEPT_DEFINED__
#define OCALL_ACCEPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_accept, (int sockfd, void* addr, uint32_t* addrlen, uint32_t addr_size));
#endif
#ifndef OCALL_BIND_DEFINED__
#define OCALL_BIND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_bind, (int sockfd, const void* addr, uint32_t addrlen));
#endif
#ifndef OCALL_CONNECT_DEFINED__
#define OCALL_CONNECT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_connect, (int sockfd, void* addr, uint32_t addrlen));
#endif
#ifndef OCALL_GETSOCKNAME_DEFINED__
#define OCALL_GETSOCKNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getsockname, (int sockfd, void* addr, uint32_t* addrlen, uint32_t addr_size));
#endif
#ifndef OCALL_GETPEERNAME_DEFINED__
#define OCALL_GETPEERNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpeername, (int sockfd, void* addr, uint32_t* addrlen, uint32_t addr_size));
#endif
#ifndef OCALL_GETSOCKOPT_DEFINED__
#define OCALL_GETSOCKOPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getsockopt, (int sockfd, int level, int optname, void* val_buf, unsigned int val_buf_size, void* len_buf));
#endif
#ifndef OCALL_LISTEN_DEFINED__
#define OCALL_LISTEN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_listen, (int sockfd, int backlog));
#endif
#ifndef OCALL_RECV_DEFINED__
#define OCALL_RECV_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recv, (int sockfd, void* buf, size_t len, int flags));
#endif
#ifndef OCALL_RECVFROM_DEFINED__
#define OCALL_RECVFROM_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recvfrom, (int sockfd, void* buf, size_t len, int flags, void* src_addr, uint32_t* addrlen, uint32_t addr_size));
#endif
#ifndef OCALL_RECVMSG_DEFINED__
#define OCALL_RECVMSG_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_recvmsg, (int sockfd, void* msg_buf, unsigned int msg_buf_size, int flags));
#endif
#ifndef OCALL_SEND_DEFINED__
#define OCALL_SEND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_send, (int sockfd, const void* buf, size_t len, int flags));
#endif
#ifndef OCALL_SENDTO_DEFINED__
#define OCALL_SENDTO_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sendto, (int sockfd, const void* buf, size_t len, int flags, void* dest_addr, uint32_t addrlen));
#endif
#ifndef OCALL_SENDMSG_DEFINED__
#define OCALL_SENDMSG_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sendmsg, (int sockfd, void* msg_buf, unsigned int msg_buf_size, int flags));
#endif
#ifndef OCALL_SETSOCKOPT_DEFINED__
#define OCALL_SETSOCKOPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_setsockopt, (int sockfd, int level, int optname, void* optval, unsigned int optlen));
#endif
#ifndef OCALL_SHUTDOWN_DEFINED__
#define OCALL_SHUTDOWN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_shutdown, (int sockfd, int how));
#endif
#ifndef OCALL_SOCKET_DEFINED__
#define OCALL_SOCKET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_socket, (int domain, int type, int protocol));
#endif

sgx_status_t ecall_handle_command(sgx_enclave_id_t eid, unsigned int cmd, uint8_t* cmd_buf, unsigned int cmd_buf_size);
sgx_status_t ecall_iwasm_main(sgx_enclave_id_t eid, uint8_t* wasm_file_buf, uint32_t wasm_file_size);
sgx_status_t ecall_read_wasm_sec(sgx_enclave_id_t eid, uint8_t** wasm_file, uint32_t* wasm_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
