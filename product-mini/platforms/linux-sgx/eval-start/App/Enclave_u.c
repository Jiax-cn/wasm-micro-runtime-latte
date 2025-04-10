#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_handle_command_t {
	unsigned int ms_cmd;
	uint8_t* ms_cmd_buf;
	unsigned int ms_cmd_buf_size;
} ms_ecall_handle_command_t;

typedef struct ms_ecall_iwasm_main_t {
	uint8_t* ms_wasm_file_buf;
	uint32_t ms_wasm_file_size;
} ms_ecall_iwasm_main_t;

typedef struct ms_ecall_read_wasm_sec_t {
	uint8_t** ms_wasm_file;
	uint32_t* ms_wasm_size;
} ms_ecall_read_wasm_sec_t;

typedef struct ms_ocall_print_t {
	int ms_retval;
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

typedef struct ms_ocall_open_t {
	int ms_retval;
	const char* ms_pathname;
	int ms_flags;
	bool ms_has_mode;
	unsigned int ms_mode;
} ms_ocall_open_t;

typedef struct ms_ocall_openat_t {
	int ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	int ms_flags;
	bool ms_has_mode;
	unsigned int ms_mode;
} ms_ocall_openat_t;

typedef struct ms_ocall_close_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_close_t;

typedef struct ms_ocall_read_t {
	ssize_t ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_read_size;
} ms_ocall_read_t;

typedef struct ms_ocall_lseek_t {
	off_t ms_retval;
	int ms_fd;
	off_t ms_offset;
	int ms_whence;
} ms_ocall_lseek_t;

typedef struct ms_ocall_ftruncate_t {
	int ms_retval;
	int ms_fd;
	off_t ms_length;
} ms_ocall_ftruncate_t;

typedef struct ms_ocall_fsync_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_fsync_t;

typedef struct ms_ocall_fdatasync_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_fdatasync_t;

typedef struct ms_ocall_isatty_t {
	int ms_retval;
	int ms_fd;
} ms_ocall_isatty_t;

typedef struct ms_ocall_fdopendir_t {
	int ms_fd;
	void** ms_p_dirp;
} ms_ocall_fdopendir_t;

typedef struct ms_ocall_readdir_t {
	void* ms_retval;
	void* ms_dirp;
} ms_ocall_readdir_t;

typedef struct ms_ocall_rewinddir_t {
	void* ms_dirp;
} ms_ocall_rewinddir_t;

typedef struct ms_ocall_seekdir_t {
	void* ms_dirp;
	long int ms_loc;
} ms_ocall_seekdir_t;

typedef struct ms_ocall_telldir_t {
	long int ms_retval;
	void* ms_dirp;
} ms_ocall_telldir_t;

typedef struct ms_ocall_closedir_t {
	int ms_retval;
	void* ms_dirp;
} ms_ocall_closedir_t;

typedef struct ms_ocall_stat_t {
	int ms_retval;
	const char* ms_pathname;
	void* ms_buf;
	unsigned int ms_buf_len;
} ms_ocall_stat_t;

typedef struct ms_ocall_fstat_t {
	int ms_retval;
	int ms_fd;
	void* ms_buf;
	unsigned int ms_buf_len;
} ms_ocall_fstat_t;

typedef struct ms_ocall_fstatat_t {
	int ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	void* ms_buf;
	unsigned int ms_buf_len;
	int ms_flags;
} ms_ocall_fstatat_t;

typedef struct ms_ocall_mkdirat_t {
	int ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	unsigned int ms_mode;
} ms_ocall_mkdirat_t;

typedef struct ms_ocall_link_t {
	int ms_retval;
	const char* ms_oldpath;
	const char* ms_newpath;
} ms_ocall_link_t;

typedef struct ms_ocall_linkat_t {
	int ms_retval;
	int ms_olddirfd;
	const char* ms_oldpath;
	int ms_newdirfd;
	const char* ms_newpath;
	int ms_flags;
} ms_ocall_linkat_t;

typedef struct ms_ocall_unlinkat_t {
	int ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	int ms_flags;
} ms_ocall_unlinkat_t;

typedef struct ms_ocall_readlink_t {
	ssize_t ms_retval;
	const char* ms_pathname;
	char* ms_buf;
	size_t ms_bufsiz;
} ms_ocall_readlink_t;

typedef struct ms_ocall_readlinkat_t {
	ssize_t ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	char* ms_buf;
	size_t ms_bufsiz;
} ms_ocall_readlinkat_t;

typedef struct ms_ocall_renameat_t {
	int ms_retval;
	int ms_olddirfd;
	const char* ms_oldpath;
	int ms_newdirfd;
	const char* ms_newpath;
} ms_ocall_renameat_t;

typedef struct ms_ocall_symlinkat_t {
	int ms_retval;
	const char* ms_target;
	int ms_newdirfd;
	const char* ms_linkpath;
} ms_ocall_symlinkat_t;

typedef struct ms_ocall_ioctl_t {
	int ms_retval;
	int ms_fd;
	unsigned long int ms_request;
	void* ms_arg;
	unsigned int ms_arg_len;
} ms_ocall_ioctl_t;

typedef struct ms_ocall_fcntl_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
} ms_ocall_fcntl_t;

typedef struct ms_ocall_fcntl_long_t {
	int ms_retval;
	int ms_fd;
	int ms_cmd;
	long int ms_arg;
} ms_ocall_fcntl_long_t;

typedef struct ms_ocall_realpath_t {
	int ms_retval;
	const char* ms_path;
	char* ms_buf;
	unsigned int ms_buf_len;
} ms_ocall_realpath_t;

typedef struct ms_ocall_posix_fallocate_t {
	int ms_retval;
	int ms_fd;
	off_t ms_offset;
	off_t ms_len;
} ms_ocall_posix_fallocate_t;

typedef struct ms_ocall_poll_t {
	int ms_retval;
	void* ms_fds;
	unsigned int ms_nfds;
	int ms_timeout;
	unsigned int ms_fds_len;
} ms_ocall_poll_t;

typedef struct ms_ocall_getopt_t {
	int ms_retval;
	int ms_argc;
	char* ms_argv_buf;
	unsigned int ms_argv_buf_len;
	const char* ms_optstring;
} ms_ocall_getopt_t;

typedef struct ms_ocall_readv_t {
	ssize_t ms_retval;
	int ms_fd;
	char* ms_iov_buf;
	unsigned int ms_buf_size;
	int ms_iovcnt;
	bool ms_has_offset;
	off_t ms_offset;
} ms_ocall_readv_t;

typedef struct ms_ocall_writev_t {
	ssize_t ms_retval;
	int ms_fd;
	char* ms_iov_buf;
	unsigned int ms_buf_size;
	int ms_iovcnt;
	bool ms_has_offset;
	off_t ms_offset;
} ms_ocall_writev_t;

typedef struct ms_ocall_clock_gettime_t {
	int ms_retval;
	unsigned int ms_clock_id;
	void* ms_tp_buf;
	unsigned int ms_tp_buf_size;
} ms_ocall_clock_gettime_t;

typedef struct ms_ocall_clock_getres_t {
	int ms_retval;
	int ms_clock_id;
	void* ms_res_buf;
	unsigned int ms_res_buf_size;
} ms_ocall_clock_getres_t;

typedef struct ms_ocall_utimensat_t {
	int ms_retval;
	int ms_dirfd;
	const char* ms_pathname;
	const void* ms_times_buf;
	unsigned int ms_times_buf_size;
	int ms_flags;
} ms_ocall_utimensat_t;

typedef struct ms_ocall_futimens_t {
	int ms_retval;
	int ms_fd;
	const void* ms_times_buf;
	unsigned int ms_times_buf_size;
} ms_ocall_futimens_t;

typedef struct ms_ocall_clock_nanosleep_t {
	int ms_retval;
	unsigned int ms_clock_id;
	int ms_flags;
	const void* ms_req_buf;
	unsigned int ms_req_buf_size;
	void* ms_rem_buf;
	unsigned int ms_rem_buf_size;
} ms_ocall_clock_nanosleep_t;

typedef struct ms_ocall_raise_t {
	int ms_retval;
	int ms_sig;
} ms_ocall_raise_t;

typedef struct ms_ocall_sched_yield_t {
	int ms_retval;
} ms_ocall_sched_yield_t;

typedef struct ms_ocall_pthread_rwlock_init_t {
	int ms_retval;
	void** ms_rwlock;
	void* ms_attr;
} ms_ocall_pthread_rwlock_init_t;

typedef struct ms_ocall_pthread_rwlock_destroy_t {
	int ms_retval;
	void* ms_rwlock;
} ms_ocall_pthread_rwlock_destroy_t;

typedef struct ms_ocall_pthread_rwlock_rdlock_t {
	int ms_retval;
	void* ms_rwlock;
} ms_ocall_pthread_rwlock_rdlock_t;

typedef struct ms_ocall_pthread_rwlock_wrlock_t {
	int ms_retval;
	void* ms_rwlock;
} ms_ocall_pthread_rwlock_wrlock_t;

typedef struct ms_ocall_pthread_rwlock_unlock_t {
	int ms_retval;
	void* ms_rwlock;
} ms_ocall_pthread_rwlock_unlock_t;

typedef struct ms_ocall_get_errno_t {
	int ms_retval;
} ms_ocall_get_errno_t;

typedef struct ms_ocall_accept_t {
	int ms_retval;
	int ms_sockfd;
	void* ms_addr;
	uint32_t* ms_addrlen;
	uint32_t ms_addr_size;
} ms_ocall_accept_t;

typedef struct ms_ocall_bind_t {
	int ms_retval;
	int ms_sockfd;
	const void* ms_addr;
	uint32_t ms_addrlen;
} ms_ocall_bind_t;

typedef struct ms_ocall_connect_t {
	int ms_retval;
	int ms_sockfd;
	void* ms_addr;
	uint32_t ms_addrlen;
} ms_ocall_connect_t;

typedef struct ms_ocall_getsockname_t {
	int ms_retval;
	int ms_sockfd;
	void* ms_addr;
	uint32_t* ms_addrlen;
	uint32_t ms_addr_size;
} ms_ocall_getsockname_t;

typedef struct ms_ocall_getpeername_t {
	int ms_retval;
	int ms_sockfd;
	void* ms_addr;
	uint32_t* ms_addrlen;
	uint32_t ms_addr_size;
} ms_ocall_getpeername_t;

typedef struct ms_ocall_getsockopt_t {
	int ms_retval;
	int ms_sockfd;
	int ms_level;
	int ms_optname;
	void* ms_val_buf;
	unsigned int ms_val_buf_size;
	void* ms_len_buf;
} ms_ocall_getsockopt_t;

typedef struct ms_ocall_listen_t {
	int ms_retval;
	int ms_sockfd;
	int ms_backlog;
} ms_ocall_listen_t;

typedef struct ms_ocall_recv_t {
	int ms_retval;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_recv_t;

typedef struct ms_ocall_recvfrom_t {
	ssize_t ms_retval;
	int ms_sockfd;
	void* ms_buf;
	size_t ms_len;
	int ms_flags;
	void* ms_src_addr;
	uint32_t* ms_addrlen;
	uint32_t ms_addr_size;
} ms_ocall_recvfrom_t;

typedef struct ms_ocall_recvmsg_t {
	ssize_t ms_retval;
	int ms_sockfd;
	void* ms_msg_buf;
	unsigned int ms_msg_buf_size;
	int ms_flags;
} ms_ocall_recvmsg_t;

typedef struct ms_ocall_send_t {
	int ms_retval;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
} ms_ocall_send_t;

typedef struct ms_ocall_sendto_t {
	ssize_t ms_retval;
	int ms_sockfd;
	const void* ms_buf;
	size_t ms_len;
	int ms_flags;
	void* ms_dest_addr;
	uint32_t ms_addrlen;
} ms_ocall_sendto_t;

typedef struct ms_ocall_sendmsg_t {
	ssize_t ms_retval;
	int ms_sockfd;
	void* ms_msg_buf;
	unsigned int ms_msg_buf_size;
	int ms_flags;
} ms_ocall_sendmsg_t;

typedef struct ms_ocall_setsockopt_t {
	int ms_retval;
	int ms_sockfd;
	int ms_level;
	int ms_optname;
	void* ms_optval;
	unsigned int ms_optlen;
} ms_ocall_setsockopt_t;

typedef struct ms_ocall_shutdown_t {
	int ms_retval;
	int ms_sockfd;
	int ms_how;
} ms_ocall_shutdown_t;

typedef struct ms_ocall_socket_t {
	int ms_retval;
	int ms_domain;
	int ms_type;
	int ms_protocol;
} ms_ocall_socket_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ms->ms_retval = ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_open(void* pms)
{
	ms_ocall_open_t* ms = SGX_CAST(ms_ocall_open_t*, pms);
	ms->ms_retval = ocall_open(ms->ms_pathname, ms->ms_flags, ms->ms_has_mode, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_openat(void* pms)
{
	ms_ocall_openat_t* ms = SGX_CAST(ms_ocall_openat_t*, pms);
	ms->ms_retval = ocall_openat(ms->ms_dirfd, ms->ms_pathname, ms->ms_flags, ms->ms_has_mode, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_close(void* pms)
{
	ms_ocall_close_t* ms = SGX_CAST(ms_ocall_close_t*, pms);
	ms->ms_retval = ocall_close(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_read(void* pms)
{
	ms_ocall_read_t* ms = SGX_CAST(ms_ocall_read_t*, pms);
	ms->ms_retval = ocall_read(ms->ms_fd, ms->ms_buf, ms->ms_read_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_lseek(void* pms)
{
	ms_ocall_lseek_t* ms = SGX_CAST(ms_ocall_lseek_t*, pms);
	ms->ms_retval = ocall_lseek(ms->ms_fd, ms->ms_offset, ms->ms_whence);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_ftruncate(void* pms)
{
	ms_ocall_ftruncate_t* ms = SGX_CAST(ms_ocall_ftruncate_t*, pms);
	ms->ms_retval = ocall_ftruncate(ms->ms_fd, ms->ms_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fsync(void* pms)
{
	ms_ocall_fsync_t* ms = SGX_CAST(ms_ocall_fsync_t*, pms);
	ms->ms_retval = ocall_fsync(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fdatasync(void* pms)
{
	ms_ocall_fdatasync_t* ms = SGX_CAST(ms_ocall_fdatasync_t*, pms);
	ms->ms_retval = ocall_fdatasync(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_isatty(void* pms)
{
	ms_ocall_isatty_t* ms = SGX_CAST(ms_ocall_isatty_t*, pms);
	ms->ms_retval = ocall_isatty(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fdopendir(void* pms)
{
	ms_ocall_fdopendir_t* ms = SGX_CAST(ms_ocall_fdopendir_t*, pms);
	ocall_fdopendir(ms->ms_fd, ms->ms_p_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readdir(void* pms)
{
	ms_ocall_readdir_t* ms = SGX_CAST(ms_ocall_readdir_t*, pms);
	ms->ms_retval = ocall_readdir(ms->ms_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_rewinddir(void* pms)
{
	ms_ocall_rewinddir_t* ms = SGX_CAST(ms_ocall_rewinddir_t*, pms);
	ocall_rewinddir(ms->ms_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_seekdir(void* pms)
{
	ms_ocall_seekdir_t* ms = SGX_CAST(ms_ocall_seekdir_t*, pms);
	ocall_seekdir(ms->ms_dirp, ms->ms_loc);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_telldir(void* pms)
{
	ms_ocall_telldir_t* ms = SGX_CAST(ms_ocall_telldir_t*, pms);
	ms->ms_retval = ocall_telldir(ms->ms_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_closedir(void* pms)
{
	ms_ocall_closedir_t* ms = SGX_CAST(ms_ocall_closedir_t*, pms);
	ms->ms_retval = ocall_closedir(ms->ms_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_stat(void* pms)
{
	ms_ocall_stat_t* ms = SGX_CAST(ms_ocall_stat_t*, pms);
	ms->ms_retval = ocall_stat(ms->ms_pathname, ms->ms_buf, ms->ms_buf_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fstat(void* pms)
{
	ms_ocall_fstat_t* ms = SGX_CAST(ms_ocall_fstat_t*, pms);
	ms->ms_retval = ocall_fstat(ms->ms_fd, ms->ms_buf, ms->ms_buf_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fstatat(void* pms)
{
	ms_ocall_fstatat_t* ms = SGX_CAST(ms_ocall_fstatat_t*, pms);
	ms->ms_retval = ocall_fstatat(ms->ms_dirfd, ms->ms_pathname, ms->ms_buf, ms->ms_buf_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_mkdirat(void* pms)
{
	ms_ocall_mkdirat_t* ms = SGX_CAST(ms_ocall_mkdirat_t*, pms);
	ms->ms_retval = ocall_mkdirat(ms->ms_dirfd, ms->ms_pathname, ms->ms_mode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_link(void* pms)
{
	ms_ocall_link_t* ms = SGX_CAST(ms_ocall_link_t*, pms);
	ms->ms_retval = ocall_link(ms->ms_oldpath, ms->ms_newpath);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_linkat(void* pms)
{
	ms_ocall_linkat_t* ms = SGX_CAST(ms_ocall_linkat_t*, pms);
	ms->ms_retval = ocall_linkat(ms->ms_olddirfd, ms->ms_oldpath, ms->ms_newdirfd, ms->ms_newpath, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_unlinkat(void* pms)
{
	ms_ocall_unlinkat_t* ms = SGX_CAST(ms_ocall_unlinkat_t*, pms);
	ms->ms_retval = ocall_unlinkat(ms->ms_dirfd, ms->ms_pathname, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readlink(void* pms)
{
	ms_ocall_readlink_t* ms = SGX_CAST(ms_ocall_readlink_t*, pms);
	ms->ms_retval = ocall_readlink(ms->ms_pathname, ms->ms_buf, ms->ms_bufsiz);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readlinkat(void* pms)
{
	ms_ocall_readlinkat_t* ms = SGX_CAST(ms_ocall_readlinkat_t*, pms);
	ms->ms_retval = ocall_readlinkat(ms->ms_dirfd, ms->ms_pathname, ms->ms_buf, ms->ms_bufsiz);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_renameat(void* pms)
{
	ms_ocall_renameat_t* ms = SGX_CAST(ms_ocall_renameat_t*, pms);
	ms->ms_retval = ocall_renameat(ms->ms_olddirfd, ms->ms_oldpath, ms->ms_newdirfd, ms->ms_newpath);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_symlinkat(void* pms)
{
	ms_ocall_symlinkat_t* ms = SGX_CAST(ms_ocall_symlinkat_t*, pms);
	ms->ms_retval = ocall_symlinkat(ms->ms_target, ms->ms_newdirfd, ms->ms_linkpath);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_ioctl(void* pms)
{
	ms_ocall_ioctl_t* ms = SGX_CAST(ms_ocall_ioctl_t*, pms);
	ms->ms_retval = ocall_ioctl(ms->ms_fd, ms->ms_request, ms->ms_arg, ms->ms_arg_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fcntl(void* pms)
{
	ms_ocall_fcntl_t* ms = SGX_CAST(ms_ocall_fcntl_t*, pms);
	ms->ms_retval = ocall_fcntl(ms->ms_fd, ms->ms_cmd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_fcntl_long(void* pms)
{
	ms_ocall_fcntl_long_t* ms = SGX_CAST(ms_ocall_fcntl_long_t*, pms);
	ms->ms_retval = ocall_fcntl_long(ms->ms_fd, ms->ms_cmd, ms->ms_arg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_realpath(void* pms)
{
	ms_ocall_realpath_t* ms = SGX_CAST(ms_ocall_realpath_t*, pms);
	ms->ms_retval = ocall_realpath(ms->ms_path, ms->ms_buf, ms->ms_buf_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_posix_fallocate(void* pms)
{
	ms_ocall_posix_fallocate_t* ms = SGX_CAST(ms_ocall_posix_fallocate_t*, pms);
	ms->ms_retval = ocall_posix_fallocate(ms->ms_fd, ms->ms_offset, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_poll(void* pms)
{
	ms_ocall_poll_t* ms = SGX_CAST(ms_ocall_poll_t*, pms);
	ms->ms_retval = ocall_poll(ms->ms_fds, ms->ms_nfds, ms->ms_timeout, ms->ms_fds_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getopt(void* pms)
{
	ms_ocall_getopt_t* ms = SGX_CAST(ms_ocall_getopt_t*, pms);
	ms->ms_retval = ocall_getopt(ms->ms_argc, ms->ms_argv_buf, ms->ms_argv_buf_len, ms->ms_optstring);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_readv(void* pms)
{
	ms_ocall_readv_t* ms = SGX_CAST(ms_ocall_readv_t*, pms);
	ms->ms_retval = ocall_readv(ms->ms_fd, ms->ms_iov_buf, ms->ms_buf_size, ms->ms_iovcnt, ms->ms_has_offset, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_writev(void* pms)
{
	ms_ocall_writev_t* ms = SGX_CAST(ms_ocall_writev_t*, pms);
	ms->ms_retval = ocall_writev(ms->ms_fd, ms->ms_iov_buf, ms->ms_buf_size, ms->ms_iovcnt, ms->ms_has_offset, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_clock_gettime(void* pms)
{
	ms_ocall_clock_gettime_t* ms = SGX_CAST(ms_ocall_clock_gettime_t*, pms);
	ms->ms_retval = ocall_clock_gettime(ms->ms_clock_id, ms->ms_tp_buf, ms->ms_tp_buf_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_clock_getres(void* pms)
{
	ms_ocall_clock_getres_t* ms = SGX_CAST(ms_ocall_clock_getres_t*, pms);
	ms->ms_retval = ocall_clock_getres(ms->ms_clock_id, ms->ms_res_buf, ms->ms_res_buf_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_utimensat(void* pms)
{
	ms_ocall_utimensat_t* ms = SGX_CAST(ms_ocall_utimensat_t*, pms);
	ms->ms_retval = ocall_utimensat(ms->ms_dirfd, ms->ms_pathname, ms->ms_times_buf, ms->ms_times_buf_size, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_futimens(void* pms)
{
	ms_ocall_futimens_t* ms = SGX_CAST(ms_ocall_futimens_t*, pms);
	ms->ms_retval = ocall_futimens(ms->ms_fd, ms->ms_times_buf, ms->ms_times_buf_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_clock_nanosleep(void* pms)
{
	ms_ocall_clock_nanosleep_t* ms = SGX_CAST(ms_ocall_clock_nanosleep_t*, pms);
	ms->ms_retval = ocall_clock_nanosleep(ms->ms_clock_id, ms->ms_flags, ms->ms_req_buf, ms->ms_req_buf_size, ms->ms_rem_buf, ms->ms_rem_buf_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_raise(void* pms)
{
	ms_ocall_raise_t* ms = SGX_CAST(ms_ocall_raise_t*, pms);
	ms->ms_retval = ocall_raise(ms->ms_sig);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sched_yield(void* pms)
{
	ms_ocall_sched_yield_t* ms = SGX_CAST(ms_ocall_sched_yield_t*, pms);
	ms->ms_retval = ocall_sched_yield();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_rwlock_init(void* pms)
{
	ms_ocall_pthread_rwlock_init_t* ms = SGX_CAST(ms_ocall_pthread_rwlock_init_t*, pms);
	ms->ms_retval = ocall_pthread_rwlock_init(ms->ms_rwlock, ms->ms_attr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_rwlock_destroy(void* pms)
{
	ms_ocall_pthread_rwlock_destroy_t* ms = SGX_CAST(ms_ocall_pthread_rwlock_destroy_t*, pms);
	ms->ms_retval = ocall_pthread_rwlock_destroy(ms->ms_rwlock);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_rwlock_rdlock(void* pms)
{
	ms_ocall_pthread_rwlock_rdlock_t* ms = SGX_CAST(ms_ocall_pthread_rwlock_rdlock_t*, pms);
	ms->ms_retval = ocall_pthread_rwlock_rdlock(ms->ms_rwlock);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_rwlock_wrlock(void* pms)
{
	ms_ocall_pthread_rwlock_wrlock_t* ms = SGX_CAST(ms_ocall_pthread_rwlock_wrlock_t*, pms);
	ms->ms_retval = ocall_pthread_rwlock_wrlock(ms->ms_rwlock);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_pthread_rwlock_unlock(void* pms)
{
	ms_ocall_pthread_rwlock_unlock_t* ms = SGX_CAST(ms_ocall_pthread_rwlock_unlock_t*, pms);
	ms->ms_retval = ocall_pthread_rwlock_unlock(ms->ms_rwlock);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_errno(void* pms)
{
	ms_ocall_get_errno_t* ms = SGX_CAST(ms_ocall_get_errno_t*, pms);
	ms->ms_retval = ocall_get_errno();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_accept(void* pms)
{
	ms_ocall_accept_t* ms = SGX_CAST(ms_ocall_accept_t*, pms);
	ms->ms_retval = ocall_accept(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen, ms->ms_addr_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_bind(void* pms)
{
	ms_ocall_bind_t* ms = SGX_CAST(ms_ocall_bind_t*, pms);
	ms->ms_retval = ocall_bind(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_connect(void* pms)
{
	ms_ocall_connect_t* ms = SGX_CAST(ms_ocall_connect_t*, pms);
	ms->ms_retval = ocall_connect(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getsockname(void* pms)
{
	ms_ocall_getsockname_t* ms = SGX_CAST(ms_ocall_getsockname_t*, pms);
	ms->ms_retval = ocall_getsockname(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen, ms->ms_addr_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getpeername(void* pms)
{
	ms_ocall_getpeername_t* ms = SGX_CAST(ms_ocall_getpeername_t*, pms);
	ms->ms_retval = ocall_getpeername(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen, ms->ms_addr_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_getsockopt(void* pms)
{
	ms_ocall_getsockopt_t* ms = SGX_CAST(ms_ocall_getsockopt_t*, pms);
	ms->ms_retval = ocall_getsockopt(ms->ms_sockfd, ms->ms_level, ms->ms_optname, ms->ms_val_buf, ms->ms_val_buf_size, ms->ms_len_buf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_listen(void* pms)
{
	ms_ocall_listen_t* ms = SGX_CAST(ms_ocall_listen_t*, pms);
	ms->ms_retval = ocall_listen(ms->ms_sockfd, ms->ms_backlog);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_recv(void* pms)
{
	ms_ocall_recv_t* ms = SGX_CAST(ms_ocall_recv_t*, pms);
	ms->ms_retval = ocall_recv(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_recvfrom(void* pms)
{
	ms_ocall_recvfrom_t* ms = SGX_CAST(ms_ocall_recvfrom_t*, pms);
	ms->ms_retval = ocall_recvfrom(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags, ms->ms_src_addr, ms->ms_addrlen, ms->ms_addr_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_recvmsg(void* pms)
{
	ms_ocall_recvmsg_t* ms = SGX_CAST(ms_ocall_recvmsg_t*, pms);
	ms->ms_retval = ocall_recvmsg(ms->ms_sockfd, ms->ms_msg_buf, ms->ms_msg_buf_size, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_send(void* pms)
{
	ms_ocall_send_t* ms = SGX_CAST(ms_ocall_send_t*, pms);
	ms->ms_retval = ocall_send(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sendto(void* pms)
{
	ms_ocall_sendto_t* ms = SGX_CAST(ms_ocall_sendto_t*, pms);
	ms->ms_retval = ocall_sendto(ms->ms_sockfd, ms->ms_buf, ms->ms_len, ms->ms_flags, ms->ms_dest_addr, ms->ms_addrlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sendmsg(void* pms)
{
	ms_ocall_sendmsg_t* ms = SGX_CAST(ms_ocall_sendmsg_t*, pms);
	ms->ms_retval = ocall_sendmsg(ms->ms_sockfd, ms->ms_msg_buf, ms->ms_msg_buf_size, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_setsockopt(void* pms)
{
	ms_ocall_setsockopt_t* ms = SGX_CAST(ms_ocall_setsockopt_t*, pms);
	ms->ms_retval = ocall_setsockopt(ms->ms_sockfd, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_shutdown(void* pms)
{
	ms_ocall_shutdown_t* ms = SGX_CAST(ms_ocall_shutdown_t*, pms);
	ms->ms_retval = ocall_shutdown(ms->ms_sockfd, ms->ms_how);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_socket(void* pms)
{
	ms_ocall_socket_t* ms = SGX_CAST(ms_ocall_socket_t*, pms);
	ms->ms_retval = ocall_socket(ms->ms_domain, ms->ms_type, ms->ms_protocol);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[73];
} ocall_table_Enclave = {
	73,
	{
		(void*)Enclave_ocall_print,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)Enclave_pthread_wait_timeout_ocall,
		(void*)Enclave_pthread_create_ocall,
		(void*)Enclave_pthread_wakeup_ocall,
		(void*)Enclave_ocall_open,
		(void*)Enclave_ocall_openat,
		(void*)Enclave_ocall_close,
		(void*)Enclave_ocall_read,
		(void*)Enclave_ocall_lseek,
		(void*)Enclave_ocall_ftruncate,
		(void*)Enclave_ocall_fsync,
		(void*)Enclave_ocall_fdatasync,
		(void*)Enclave_ocall_isatty,
		(void*)Enclave_ocall_fdopendir,
		(void*)Enclave_ocall_readdir,
		(void*)Enclave_ocall_rewinddir,
		(void*)Enclave_ocall_seekdir,
		(void*)Enclave_ocall_telldir,
		(void*)Enclave_ocall_closedir,
		(void*)Enclave_ocall_stat,
		(void*)Enclave_ocall_fstat,
		(void*)Enclave_ocall_fstatat,
		(void*)Enclave_ocall_mkdirat,
		(void*)Enclave_ocall_link,
		(void*)Enclave_ocall_linkat,
		(void*)Enclave_ocall_unlinkat,
		(void*)Enclave_ocall_readlink,
		(void*)Enclave_ocall_readlinkat,
		(void*)Enclave_ocall_renameat,
		(void*)Enclave_ocall_symlinkat,
		(void*)Enclave_ocall_ioctl,
		(void*)Enclave_ocall_fcntl,
		(void*)Enclave_ocall_fcntl_long,
		(void*)Enclave_ocall_realpath,
		(void*)Enclave_ocall_posix_fallocate,
		(void*)Enclave_ocall_poll,
		(void*)Enclave_ocall_getopt,
		(void*)Enclave_ocall_readv,
		(void*)Enclave_ocall_writev,
		(void*)Enclave_ocall_clock_gettime,
		(void*)Enclave_ocall_clock_getres,
		(void*)Enclave_ocall_utimensat,
		(void*)Enclave_ocall_futimens,
		(void*)Enclave_ocall_clock_nanosleep,
		(void*)Enclave_ocall_raise,
		(void*)Enclave_ocall_sched_yield,
		(void*)Enclave_ocall_pthread_rwlock_init,
		(void*)Enclave_ocall_pthread_rwlock_destroy,
		(void*)Enclave_ocall_pthread_rwlock_rdlock,
		(void*)Enclave_ocall_pthread_rwlock_wrlock,
		(void*)Enclave_ocall_pthread_rwlock_unlock,
		(void*)Enclave_ocall_get_errno,
		(void*)Enclave_ocall_accept,
		(void*)Enclave_ocall_bind,
		(void*)Enclave_ocall_connect,
		(void*)Enclave_ocall_getsockname,
		(void*)Enclave_ocall_getpeername,
		(void*)Enclave_ocall_getsockopt,
		(void*)Enclave_ocall_listen,
		(void*)Enclave_ocall_recv,
		(void*)Enclave_ocall_recvfrom,
		(void*)Enclave_ocall_recvmsg,
		(void*)Enclave_ocall_send,
		(void*)Enclave_ocall_sendto,
		(void*)Enclave_ocall_sendmsg,
		(void*)Enclave_ocall_setsockopt,
		(void*)Enclave_ocall_shutdown,
		(void*)Enclave_ocall_socket,
	}
};
sgx_status_t ecall_handle_command(sgx_enclave_id_t eid, unsigned int cmd, uint8_t* cmd_buf, unsigned int cmd_buf_size)
{
	sgx_status_t status;
	ms_ecall_handle_command_t ms;
	ms.ms_cmd = cmd;
	ms.ms_cmd_buf = cmd_buf;
	ms.ms_cmd_buf_size = cmd_buf_size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_iwasm_main(sgx_enclave_id_t eid, uint8_t* wasm_file_buf, uint32_t wasm_file_size)
{
	sgx_status_t status;
	ms_ecall_iwasm_main_t ms;
	ms.ms_wasm_file_buf = wasm_file_buf;
	ms.ms_wasm_file_size = wasm_file_size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_read_wasm_sec(sgx_enclave_id_t eid, uint8_t** wasm_file, uint32_t* wasm_size)
{
	sgx_status_t status;
	ms_ecall_read_wasm_sec_t ms;
	ms.ms_wasm_file = wasm_file;
	ms.ms_wasm_size = wasm_size;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

