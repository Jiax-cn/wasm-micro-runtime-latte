#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wasm_export.h"
#include "bh_platform.h"
#include "wasm_runtime_common.h"

#include "latte.h"
#include "latte_wasm.h"

#include <unistd.h>

typedef enum _tee_runtime {
    UNKOWN = 0,
    SGX_RUNTIME = 1,
    PENGLAI_RUNTIME = 2,
}tee_runtime;

typedef union _tee_measurement {
    latte_sgx_measurement_t sgx_mr;
    latte_penglai_measurement_t penglai_mr;
}tee_measurement;

typedef struct _latte_attest_msg
{
    portid_t port_id;
    tee_measurement tee_mr; 

    uint32_t latte_index;
    uint32_t runtime_index;
}latte_attest_msg;

const char *kTargetIpAddr = "172.20.10.4";
const int kTargetPort = 2592;
const int kMaxIpAddrSize = 20;
const uint32_t kBufSize = 4096;

/***************utils***************/

static
void os_print_0x(void *buf, uint64_t size)
{
    uint8_t *out_buf = (uint8_t*)buf;
    for (uint64_t i = 0; i < size; i++)
    {
        os_printf("%02x ", out_buf[i]);
        if (! ((i+1) % 16)) 
        {
            os_printf("\n");
        }
    }
    if(size % 16)
    {
        os_printf("\n");
    }
    os_printf("\n");
}

/**************TEE API**************/

#if BUILD_LATTE_SGX == 1
    #include "sgx_wasm.h"
    #include "sgx_utils.h"
    #define PORTMR_TEE_API(x) sgx_##x
    #define GET_TEE_REPORT(p) memcpy(p, &sgx_self_report()->body.mr_enclave, SGX_HASH_SIZE)
    tee_runtime native_runtime=SGX_RUNTIME;

#elif BUILD_LATTE_PENGLAI == 1
    #include "eapp_pm_wasm.h"
    #include "eapp.h"
    #define PORTMR_TEE_API(x) penglai_##x
    #define GET_TEE_REPORT(p)                                           \
    do {                                                                \
        struct report_t rpt;                                            \
        get_init_report(NULL, &rpt, 0);                                 \
        memcpy(p, (uint8_t *)(rpt.enclave.hash), SM3_DIGEST_LENGTH);    \
    } while (0)
    tee_runtime native_runtime=PENGLAI_RUNTIME;
#else
    uint8_t *stub_get_wasm_sec_addr() {return NULL;} 
    uint8_t *stub_get_wasm_common_addr() {return NULL;}
    uint32_t stub_get_wasm_size() {return 0;}
    uint8_t *stub_get_wasm() {return NULL;}
    #define PORTMR_TEE_API(x) stub_##x
    #define GET_TEE_REPORT(p) (void) p
    tee_runtime native_runtime=UNKOWN;
#endif

static
uint8_t *get_runtime_common(uint32_t *ret_rt_comm_size)
{
    *ret_rt_comm_size = WASM_COMMON_SEC_SIZE;
    return PORTMR_TEE_API(get_wasm_common_addr());
}

/***************wasm api***************/

static int
latte_attest_wrapper(wasm_exec_env_t exec_env, uint8_t *ret_secret, uint32_t *ret_size)
{
    wasm_module_t module = wasm_exec_env_get_module(exec_env);
    uint8_t *wasm_sec = NULL;
    latte_attest_msg msg;
    bh_socket_t sockfd;
    uint8_t secret[kBufSize];

    wasm_sec = PORTMR_TEE_API(get_wasm_sec_addr());
    memcpy(msg.port_id, wasm_sec, sizeof(portid_t));

    memset(&msg.tee_mr, 0, sizeof(tee_measurement));
    GET_TEE_REPORT(&msg.tee_mr);

    msg.latte_index = wasm_runtime_get_latte_index(module);
    msg.runtime_index = (uint32_t)native_runtime;

    if (os_socket_create(&sockfd, true, true) != 0)
    {
        os_printf("ERROR create socket\n");
        return -1;
    }
    if (os_socket_connect(sockfd, kTargetIpAddr, kTargetPort))
    {
        os_printf("ERROR connect other tee runtime\n");
        os_socket_close(sockfd);
        return -1;
    }    
    if (os_socket_send(sockfd, ((char *)&msg), sizeof(latte_attest_msg)) != sizeof(latte_attest_msg)) {
        os_printf("failed to send\n");
        return -1;
    } 

    memset(secret, 0, kBufSize);
    *ret_size = os_socket_recv(sockfd, secret, kBufSize);
    memcpy(ret_secret, secret, *ret_size);

    os_socket_close(sockfd);
    return 0;
}

static int
latte_verify_msg(wasm_exec_env_t exec_env, latte_attest_msg *msg)
{
    wasm_module_t module = wasm_exec_env_get_module(exec_env);
    uint32_t portid_data_size = 0, portid_sec_size = 0;
    uint8_t *portid_data = NULL, *portid_sec = NULL;
    portid_t ref_id;

    portid_data = (uint8_t *)wasm_runtime_get_custom_section(module, kSectionName, &portid_data_size);
    if (!portid_data) {
        os_printf("Wasm custom section not found.\n");
        return -1;
    }

    portid_sec = serialize_portid_section((uint8_t *)portid_data, portid_data_size, &portid_sec_size);

    derive_portid(*(portid_state_t *)(portid_data + (msg->latte_index) * sizeof(portid_state_t)), portid_sec, portid_sec_size, ref_id);

    // os_printf("reference portable identity:\n");
    // os_print_0x(ref_id, sizeof(portid_t));

    if (memcmp(ref_id, msg->port_id, sizeof(portid_t)) != 0) {
        os_printf("invalid portable identity\n");
        return 1;
    }

    uint8_t *rt_comm = NULL;
    uint32_t rt_comm_size = 0;
    tee_measurement ref_mr = {0};

    rt_comm = get_runtime_common(&rt_comm_size);

    switch (msg->runtime_index) 
    {
    case SGX_RUNTIME: 
        sgx_derive_hardcode_portid(*(sgx_hash_state_t *)(rt_comm + sizeof(uint32_t)), ref_id, rt_comm, ref_mr.sgx_mr);
        break;
    case PENGLAI_RUNTIME:
        penglai_derive_hardcode_portid(*(penglai_hash_state_t *)(rt_comm + sizeof(uint32_t) + sizeof(sgx_hash_state_t)), ref_id, rt_comm, 0, ref_mr.penglai_mr);
        break;
    default:
        os_printf("invalid runtime index received\n");
        return -1;
    }

    // os_printf("reference measurement:\n");
    // os_print_0x(&ref_mr, sizeof(tee_measurement));

    if (memcmp(&ref_mr, &msg->tee_mr, sizeof(tee_measurement)) != 0) {
        os_printf("invalid measurement\n");
        return 2;
    }

    return 0;
}

static int
latte_verify_wrapper(wasm_exec_env_t exec_env, uint8_t *secret, uint32_t secret_size)
{
    bh_socket_t sockfd, t_sockfd;
    int target_port = kTargetPort;
    char t_addr[kMaxIpAddrSize];
    uint32_t t_addr_size = kMaxIpAddrSize;
    uint8_t buf[kBufSize];

    if (os_socket_create(&sockfd, true, true) != 0)
    {
        os_printf("ERROR create socket\n");
        return -1;
    }

    if (os_socket_bind(sockfd, kTargetIpAddr, (int *)&target_port) != 0)
    {
        os_printf("ERROR socket bind\n");
        return -1;
    }

    if (os_socket_listen(sockfd, 1) != 0)
    {
        os_printf("ERROR socket listen\n");
        return -1;
    }

    if (os_socket_accept(sockfd, &t_sockfd, t_addr, &t_addr_size) != 0)
    {
        os_printf("ERROR socket accept\n");
        return -1;
    }

    os_socket_recv(t_sockfd, buf, kBufSize);

    if (latte_verify_msg(exec_env, (latte_attest_msg *)buf) == 0)
    {
        if (secret_size > kBufSize)
        {
            os_printf("ERROR secret size exceeded\n");
            secret_size = kBufSize;
        }
        memset(buf, 0, kBufSize);
        memcpy(buf, secret, secret_size);
        os_socket_send(t_sockfd, (char *)buf, secret_size);
        os_socket_close(t_sockfd);
    }

    os_socket_close(sockfd);
    return 0;
}

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }
/* clang-format on */

static NativeSymbol native_symbols_lib_latte[] = {
    REG_NATIVE_FUNC(latte_attest, "(**)i"),
    REG_NATIVE_FUNC(latte_verify, "(*~)i"),
};

uint32_t
get_lib_latte_export_apis(NativeSymbol **p_lib_latte_apis)
{
    *p_lib_latte_apis = native_symbols_lib_latte;
    return sizeof(native_symbols_lib_latte) / sizeof(NativeSymbol);
}
