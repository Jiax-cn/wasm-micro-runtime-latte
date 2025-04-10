/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

static os_print_function_t print_function = NULL;

int
bh_platform_init()
{
    return 0;
}

void
bh_platform_destroy()
{}

void *
os_malloc(unsigned size)
{
    return malloc(size);
}

void *
os_realloc(void *ptr, unsigned size)
{
    return realloc(ptr, size);
}

void
os_free(void *ptr)
{
    free(ptr);
}

void
os_set_print_function(os_print_function_t pf)
{
    print_function = pf;
}

#define FIXED_BUFFER_SIZE 4096

int
os_printf(const char *message, ...)
{
    if (print_function != NULL) {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        va_list ap;
        va_start(ap, message);
        vsnprintf(msg, FIXED_BUFFER_SIZE, message, ap);
        va_end(ap);
        print_function(msg);
    }

    return 0;
}

int
os_vprintf(const char *format, va_list arg)
{
    if (print_function != NULL) {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        vsnprintf(msg, FIXED_BUFFER_SIZE, format, arg);
        print_function(msg);
    }

    return 0;
}

uint64
os_time_get_boot_microsecond(void)
{
    return 0;
}

#define LOG_DEBUG_SOCKET os_printf
#define LOG_DEBUG  
/* ----- Socket Related Begin ----- */
static void
textual_addr_to_sockaddr(const char *textual, int port, struct sockaddr_in *out)
{
    assert(textual);

    out->sin_family = AF_INET;
    out->sin_port = htons(port);
    out->sin_addr.s_addr = inet_addr(textual);
}

int
os_socket_create(bh_socket_t *sock, bool is_ipv4, bool is_tcp)
{
    int af;

    if (!sock) {
        return BHT_ERROR;
    }

    if (is_ipv4) {
        af = AF_INET;
    }
    else {
        errno = ENOSYS;
        return BHT_ERROR;
    }

    if (is_tcp) {
        *sock = eapp_socket(af, SOCK_STREAM, IPPROTO_TCP);
    }
    else {
        *sock = eapp_socket(af, SOCK_DGRAM, 0);
    }
    return (*sock == -1) ? BHT_ERROR : BHT_OK;
}

int
os_socket_connect(bh_socket_t socket, const char *addr, int port)
{
    struct sockaddr_in addr_in = { 0 };
    socklen_t addr_len = sizeof(struct sockaddr_in);
    int ret = 0;

    textual_addr_to_sockaddr(addr, port, &addr_in);
    ret = eapp_socket_connect(socket, (struct sockaddr *)&addr_in, addr_len);
    if (ret == -1) {
        return BHT_ERROR;
    }

    return BHT_OK;
}

int
os_socket_send(bh_socket_t socket, const void *buf, unsigned int len)
{
    return eapp_socket_send(socket, buf, len, 0);
}

int
os_socket_recv(bh_socket_t socket, void *buf, unsigned int len)
{
    return eapp_socket_recv(socket, buf, len, 0);
}

/* 
 * The above are implemented to provide service as a client, 
 * the below are unimplemented as a server due to time limitation,
 * they can be implemented in the same way, i.e. adding OCALL in Penglai.
 */

int
os_socket_shutdown(bh_socket_t socket)
{
    eapp_socket_shutdown(socket, SHUT_RDWR);
    return BHT_OK;
}

int
os_socket_set_send_timeout(bh_socket_t socket, uint64 timeout_us)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_send_timeout(bh_socket_t socket, uint64 *timeout_us)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_recv_timeout(bh_socket_t socket, uint64 timeout_us)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_recv_timeout(bh_socket_t socket, uint64 *timeout_us)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_send_buf_size(bh_socket_t socket, size_t bufsiz)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_send_buf_size(bh_socket_t socket, size_t *bufsiz)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_recv_buf_size(bh_socket_t socket, size_t bufsiz)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_recv_buf_size(bh_socket_t socket, size_t *bufsiz)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_broadcast(bh_socket_t socket, bool is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_broadcast(bh_socket_t socket, bool *is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_keep_alive(bh_socket_t socket, bool is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_keep_alive(bh_socket_t socket, bool *is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_reuse_addr(bh_socket_t socket, bool is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_reuse_addr(bh_socket_t socket, bool *is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_reuse_port(bh_socket_t socket, bool is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_reuse_port(bh_socket_t socket, bool *is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_tcp_no_delay(bh_socket_t socket, bool is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_tcp_no_delay(bh_socket_t socket, bool *is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_tcp_quick_ack(bh_socket_t socket, bool is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_tcp_quick_ack(bh_socket_t socket, bool *is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_tcp_keep_idle(bh_socket_t socket, uint32 time_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_tcp_keep_idle(bh_socket_t socket, uint32 *time_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_tcp_keep_intvl(bh_socket_t socket, uint32 time_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_tcp_keep_intvl(bh_socket_t socket, uint32 *time_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_tcp_fastopen_connect(bh_socket_t socket, bool is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_tcp_fastopen_connect(bh_socket_t socket, bool *is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_ip_ttl(bh_socket_t socket, uint8_t ttl_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_ip_ttl(bh_socket_t socket, uint8_t *ttl_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_ip_multicast_ttl(bh_socket_t socket, uint8_t ttl_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_ip_multicast_ttl(bh_socket_t socket, uint8_t *ttl_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_ipv6_only(bh_socket_t socket, bool is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_ipv6_only(bh_socket_t socket, bool *is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_linger(bh_socket_t socket, bool *is_enabled, int *linger_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_ip_add_membership(bh_socket_t socket,
                                bh_ip_addr_buffer_t *imr_multiaddr,
                                uint32_t imr_interface, bool is_ipv6)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_ip_drop_membership(bh_socket_t socket,
                                 bh_ip_addr_buffer_t *imr_multiaddr,
                                 uint32_t imr_interface, bool is_ipv6)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_ip_multicast_loop(bh_socket_t socket, bool ipv6, bool is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_recv_from(bh_socket_t socket, void *buf, unsigned int len, int flags,
                    bh_sockaddr_t *src_addr)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_send_to(bh_socket_t socket, const void *buf, unsigned int len,
                  int flags, const bh_sockaddr_t *dest_addr)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_addr_resolve(const char *host, const char *service,
                       uint8_t *hint_is_tcp, uint8_t *hint_is_ipv4,
                       bh_addr_info_t *addr_info, size_t addr_info_size,
                       size_t *max_info_size)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_linger(bh_socket_t socket, bool is_enabled, int linger_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_ip_multicast_loop(bh_socket_t socket, bool ipv6, bool *is_enabled)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_addr_local(bh_socket_t socket, bh_sockaddr_t *sockaddr)
{
    return BHT_OK;
}

int
os_socket_addr_remote(bh_socket_t socket, bh_sockaddr_t *sockaddr)
{
    return BHT_OK;
}

int
os_socket_close(bh_socket_t socket)
{
    return BHT_OK;
}

int
os_socket_bind(bh_socket_t socket, const char *host, int *port)
{
    return BHT_OK;
}

int
os_socket_listen(bh_socket_t socket, int max_client)
{
    return BHT_OK;
}

int
os_socket_accept(bh_socket_t server_sock, bh_socket_t *sock, void *addr,
                 unsigned int *addrlen)
{
    return BHT_OK;
}

int
os_socket_inet_network(bool is_ipv4, const char *cp, bh_ip_addr_buffer_t *out)
{
    return BHT_OK;
}

int
puts(const char *s)
{
    return 0;
}
/* ----- Socket Related End ----- */


/* ----- Thread Related Begin ----- */
typedef struct {
    thread_start_routine_t start;
    void *arg;
} thread_wrapper_arg;


static void *
os_thread_wrapper(void *arg)
{
    return NULL;
}

int
os_thread_create_with_prio(korp_tid *tid, thread_start_routine_t start,
                           void *arg, unsigned int stack_size, int prio)
{
    return BHT_OK;
}

int
os_thread_create(korp_tid *tid, thread_start_routine_t start, void *arg,
                 unsigned int stack_size)
{
    return BHT_OK;
}

korp_tid
os_self_thread()
{
    return 0;
}

int
os_mutex_init(korp_mutex *mutex)
{
    return BHT_OK;
}

int
os_recursive_mutex_init(korp_mutex *mutex)
{
    return BHT_OK;
}

int
os_mutex_destroy(korp_mutex *mutex)
{
    return BHT_OK;
}

int
os_mutex_lock(korp_mutex *mutex)
{
    return BHT_OK;
}

int
os_mutex_unlock(korp_mutex *mutex)
{
    return BHT_OK;
}

int
os_cond_init(korp_cond *cond)
{
    return BHT_OK;
}

int
os_cond_destroy(korp_cond *cond)
{
    return BHT_OK;
}

int
os_cond_wait(korp_cond *cond, korp_mutex *mutex)
{
    return BHT_OK;
}

static void
msec_nsec_to_abstime(struct timespec *ts, uint64 usec)
{
    // TODO
}

int
os_cond_reltimedwait(korp_cond *cond, korp_mutex *mutex, uint64 useconds)
{
    return BHT_OK;
}

int
os_cond_signal(korp_cond *cond)
{
    return BHT_OK;
}

int
os_cond_broadcast(korp_cond *cond)
{
    return BHT_OK;
}

int
os_thread_join(korp_tid thread, void **value_ptr)
{
    return BHT_OK;
}

int
os_thread_detach(korp_tid thread)
{
    return BHT_OK;
}

void
os_thread_exit(void *retval)
{
    // TODO
}

uint8 *
os_thread_get_stack_boundary()
{
    /* TODO: get sgx stack boundary */
    return NULL;
}

void
os_thread_jit_write_protect_np(bool enabled)
{}

/* ----- Thread Related End ----- */

/* ----- MMAP Related Begin ----- */
void *
os_mmap(void *hint, size_t size, int prot, int flags)
{
    void *ret = NULL;
    unsigned long aligned_size = (size + PENGLAI_PG_SIZE - 1) / PENGLAI_PG_SIZE * PENGLAI_PG_SIZE;

    ret = eapp_mmap(hint, aligned_size);
    return ret;
}

void
os_munmap(void *addr, size_t size)
{
    eapp_unmap(addr, size);
    return;
}

int
os_mprotect(void *addr, size_t size, int prot)
{
    return 0;
}

int
os_dumps_proc_mem_info(char *out, unsigned int size)
{
    return -1;
}

void
os_dcache_flush(void)
{}

void
os_icache_flush(void *start, size_t len)
{}
/* ----- MMAP Related Begin ----- */
