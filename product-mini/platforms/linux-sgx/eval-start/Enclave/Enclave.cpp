/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

#include "Enclave_t.h"
#include "wasm_export.h"
#include "bh_platform.h"
#include "sgx_wasm.h"

#include "crypto/sha256.h"
#include "latte_wasm.h"
#include "latte.h"

#if WASM_ENABLE_LIB_RATS != 0
#include <openssl/sha.h>
#endif

extern "C" {
typedef int (*os_print_function_t)(const char *message);
extern void
os_set_print_function(os_print_function_t pf);

int
enclave_print(const char *message)
{
    int bytes_written = 0;

    if (SGX_SUCCESS != ocall_print(&bytes_written, message))
        return 0;

    return bytes_written;
}
}

static int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    enclave_print(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

typedef enum EcallCmd {
    CMD_INIT_RUNTIME = 0,     /* wasm_runtime_init/full_init() */
    CMD_LOAD_MODULE,          /* wasm_runtime_load() */
    CMD_INSTANTIATE_MODULE,   /* wasm_runtime_instantiate() */
    CMD_LOOKUP_FUNCTION,      /* wasm_runtime_lookup_function() */
    CMD_CREATE_EXEC_ENV,      /* wasm_runtime_create_exec_env() */
    CMD_CALL_WASM,            /* wasm_runtime_call_wasm */
    CMD_EXEC_APP_FUNC,        /* wasm_application_execute_func() */
    CMD_EXEC_APP_MAIN,        /* wasm_application_execute_main() */
    CMD_GET_EXCEPTION,        /* wasm_runtime_get_exception() */
    CMD_DEINSTANTIATE_MODULE, /* wasm_runtime_deinstantiate() */
    CMD_UNLOAD_MODULE,        /* wasm_runtime_unload() */
    CMD_DESTROY_RUNTIME,      /* wasm_runtime_destroy() */
    CMD_SET_WASI_ARGS,        /* wasm_runtime_set_wasi_args() */
    CMD_SET_LOG_LEVEL,        /* bh_log_set_verbose_level() */
    CMD_GET_VERSION,          /* wasm_runtime_get_version() */
#if WASM_ENABLE_STATIC_PGO != 0
    CMD_GET_PGO_PROF_BUF_SIZE,  /* wasm_runtime_get_pro_prof_data_size() */
    CMD_DUMP_PGO_PROF_BUF_DATA, /* wasm_runtime_dump_pgo_prof_data_to_buf() */
#endif
} EcallCmd;

typedef struct EnclaveModule {
    wasm_module_t module;
    uint8 *wasm_file;
    uint32 wasm_file_size;
    char *wasi_arg_buf;
    char **wasi_dir_list;
    uint32 wasi_dir_list_size;
    char **wasi_env_list;
    uint32 wasi_env_list_size;
    char **wasi_addr_pool_list;
    uint32 wasi_addr_pool_list_size;
    char **wasi_argv;
    uint32 wasi_argc;
    bool is_xip_file;
    uint32 total_size_mapped;
#if WASM_ENABLE_LIB_RATS != 0
    char module_hash[SHA256_DIGEST_LENGTH];
    struct EnclaveModule *next;
#endif
} EnclaveModule;

#if WASM_ENABLE_LIB_RATS != 0
static EnclaveModule *enclave_module_list = NULL;
static korp_mutex enclave_module_list_lock = OS_THREAD_MUTEX_INITIALIZER;
#endif

#if WASM_ENABLE_GLOBAL_HEAP_POOL != 0
static char global_heap_buf[WASM_GLOBAL_HEAP_SIZE] = { 0 };
#endif

static void
set_error_buf(char *error_buf, uint32 error_buf_size, const char *string)
{
    if (error_buf != NULL)
        snprintf(error_buf, error_buf_size, "%s", string);
}

static bool runtime_inited = false;

static void
handle_cmd_init_runtime(uint64 *args, uint32 argc)
{
    uint32 max_thread_num;
    RuntimeInitArgs init_args;

    bh_assert(argc == 1);

    /* avoid duplicated init */
    if (runtime_inited) {
        args[0] = false;
        return;
    }

    os_set_print_function(enclave_print);

    max_thread_num = (uint32)args[0];

    memset(&init_args, 0, sizeof(RuntimeInitArgs));
    init_args.max_thread_num = max_thread_num;

#if WASM_ENABLE_GLOBAL_HEAP_POOL != 0
    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);
#else
    init_args.mem_alloc_type = Alloc_With_System_Allocator;
#endif

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        LOG_ERROR("Init runtime environment failed.\n");
        args[0] = false;
        return;
    }

    runtime_inited = true;
    args[0] = true;

    LOG_VERBOSE("Init runtime environment success.\n");
}

static void
handle_cmd_destroy_runtime()
{
    if (!runtime_inited)
        return;

    wasm_runtime_destroy();
    runtime_inited = false;

    LOG_VERBOSE("Destroy runtime success.\n");
}

static uint8 *
align_ptr(const uint8 *p, uint32 b)
{
    uintptr_t v = (uintptr_t)p;
    uintptr_t m = b - 1;
    return (uint8 *)((v + m) & ~m);
}

#define AOT_SECTION_TYPE_TARGET_INFO 0
#define AOT_SECTION_TYPE_SIGANATURE 6
#define E_TYPE_XIP 4

#define CHECK_BUF(buf, buf_end, length)                      \
    do {                                                     \
        if ((uintptr_t)buf + length < (uintptr_t)buf         \
            || (uintptr_t)buf + length > (uintptr_t)buf_end) \
            return false;                                    \
    } while (0)

#define read_uint16(p, p_end, res)                 \
    do {                                           \
        p = (uint8 *)align_ptr(p, sizeof(uint16)); \
        CHECK_BUF(p, p_end, sizeof(uint16));       \
        res = *(uint16 *)p;                        \
        p += sizeof(uint16);                       \
    } while (0)

#define read_uint32(p, p_end, res)                 \
    do {                                           \
        p = (uint8 *)align_ptr(p, sizeof(uint32)); \
        CHECK_BUF(p, p_end, sizeof(uint32));       \
        res = *(uint32 *)p;                        \
        p += sizeof(uint32);                       \
    } while (0)

static bool
is_xip_file(const uint8 *buf, uint32 size)
{
    const uint8 *p = buf, *p_end = buf + size;
    uint32 section_type, section_size;
    uint16 e_type;

    if (get_package_type(buf, size) != Wasm_Module_AoT)
        return false;

    CHECK_BUF(p, p_end, 8);
    p += 8;
    while (p < p_end) {
        read_uint32(p, p_end, section_type);
        read_uint32(p, p_end, section_size);
        CHECK_BUF(p, p_end, section_size);

        if (section_type == AOT_SECTION_TYPE_TARGET_INFO) {
            p += 4;
            read_uint16(p, p_end, e_type);
            return (e_type == E_TYPE_XIP) ? true : false;
        }
        else if (section_type >= AOT_SECTION_TYPE_SIGANATURE) {
            return false;
        }
        p += section_size;
    }

    return false;
}

static void
handle_cmd_load_module(uint64 *args, uint32 argc)
{
    uint64 *args_org = args;
    char *wasm_file = *(char **)args++;
    uint32 wasm_file_size = *(uint32 *)args++;
    char *error_buf = *(char **)args++;
    uint32 error_buf_size = *(uint32 *)args++;
    uint64 total_size = sizeof(EnclaveModule) + (uint64)wasm_file_size;
    EnclaveModule *enclave_module;

    bh_assert(argc == 4);

    if (!runtime_inited) {
        *(void **)args_org = NULL;
        return;
    }

    if (!is_xip_file((uint8 *)wasm_file, wasm_file_size)) {
        if (total_size >= UINT32_MAX
            || !(enclave_module = (EnclaveModule *)wasm_runtime_malloc(
                     (uint32)total_size))) {
            set_error_buf(error_buf, error_buf_size,
                          "WASM module load failed: "
                          "allocate memory failed.");
            *(void **)args_org = NULL;
            return;
        }
        memset(enclave_module, 0, (uint32)total_size);
    }
    else {
        int map_prot = MMAP_PROT_READ | MMAP_PROT_WRITE | MMAP_PROT_EXEC;
        int map_flags = MMAP_MAP_NONE;

        if (total_size >= UINT32_MAX
            || !(enclave_module = (EnclaveModule *)os_mmap(
                     NULL, (uint32)total_size, map_prot, map_flags))) {
            set_error_buf(error_buf, error_buf_size,
                          "WASM module load failed: mmap memory failed.");
            *(void **)args_org = NULL;
            return;
        }
        memset(enclave_module, 0, (uint32)total_size);
        enclave_module->is_xip_file = true;
        enclave_module->total_size_mapped = (uint32)total_size;
    }

    enclave_module->wasm_file = (uint8 *)enclave_module + sizeof(EnclaveModule);
    bh_memcpy_s(enclave_module->wasm_file, wasm_file_size, wasm_file,
                wasm_file_size);

    if (!(enclave_module->module =
              wasm_runtime_load(enclave_module->wasm_file, wasm_file_size,
                                error_buf, error_buf_size))) {
        if (!enclave_module->is_xip_file)
            wasm_runtime_free(enclave_module);
        else
            os_munmap(enclave_module, (uint32)total_size);
        *(void **)args_org = NULL;
        return;
    }

    *(EnclaveModule **)args_org = enclave_module;

#if WASM_ENABLE_LIB_RATS != 0
    /* Calculate the module hash */
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, wasm_file, wasm_file_size);
    SHA256_Final((unsigned char *)enclave_module->module_hash, &sha256);

    /* Insert enclave module to enclave module list */
    os_mutex_lock(&enclave_module_list_lock);
    enclave_module->next = enclave_module_list;
    enclave_module_list = enclave_module;
    os_mutex_unlock(&enclave_module_list_lock);
#endif

    uint32 iteration = 1;
    while (iteration --)
    {
        uint8 *reference_portid = sgx_get_wasm_sec_addr();

        uint8 *portid_sec = NULL;
        uint32 portid_sec_size, sec_content_size;
        portid_state_t portid_state;
        portid_t portid;

        deserialize_portid_section((uint8 *)wasm_file, wasm_file_size, &portid_sec, &portid_sec_size, &sec_content_size);

        gen_portid_state((uint8 *)wasm_file, wasm_file_size-portid_sec_size, portid_state);
        derive_portid(portid_state, portid_sec, portid_sec_size, portid);

        if (memcmp(portid, reference_portid, SHA256_DIGEST_LENGTH) != 0)
        {
            printf("Error: wasm measurement not match!\n");
            return;
        }
        
        uint8 *portid_data = NULL;
        uint32 portid_data_size = 0, offset = 0;
        portid_t tmp_portid;
        uint32 flag = 0;
        portid_data = (uint8_t *)wasm_runtime_get_custom_section(enclave_module->module, kSectionName, &portid_data_size);

        for (offset = 0; offset < portid_data_size; offset+=sizeof(portid_state_t)) {
            derive_portid(*(portid_state_t *)(portid_data + offset), portid_sec, portid_sec_size, tmp_portid);
            if (memcmp(portid, tmp_portid, SHA256_DIGEST_LENGTH) == 0) {
                wasm_runtime_set_latte_index(enclave_module->module, offset/sizeof(portid_state_t));
                // printf("Set latte index = %u\n", wasm_runtime_get_latte_index(enclave_module->module));
                flag = 1;
                break;
            }
        }

        if (flag == 0) {
            printf("Invalid portid section: wasm not in latte group!\n");
        }

    }

    LOG_VERBOSE("Load module success.\n");
}

static void
handle_cmd_unload_module(uint64 *args, uint32 argc)
{
    EnclaveModule *enclave_module = *(EnclaveModule **)args++;

    bh_assert(argc == 1);

    if (!runtime_inited) {
        return;
    }

#if WASM_ENABLE_LIB_RATS != 0
    /* Remove enclave module from enclave module list */
    os_mutex_lock(&enclave_module_list_lock);

    EnclaveModule *node_prev = NULL;
    EnclaveModule *node = enclave_module_list;

    while (node && node != enclave_module) {
        node_prev = node;
        node = node->next;
    }
    bh_assert(node == enclave_module);

    if (!node_prev)
        enclave_module_list = node->next;
    else
        node_prev->next = node->next;

    os_mutex_unlock(&enclave_module_list_lock);
#endif

    /* Destroy enclave module resources */
    if (enclave_module->wasi_arg_buf)
        wasm_runtime_free(enclave_module->wasi_arg_buf);

    wasm_runtime_unload(enclave_module->module);
    if (!enclave_module->is_xip_file)
        wasm_runtime_free(enclave_module);
    else
        os_munmap(enclave_module, enclave_module->total_size_mapped);

    LOG_VERBOSE("Unload module success.\n");
}

#if WASM_ENABLE_LIB_RATS != 0
char *
wasm_runtime_get_module_hash(wasm_module_t module)
{
    EnclaveModule *enclave_module;
    char *module_hash = NULL;

    os_mutex_lock(&enclave_module_list_lock);

    enclave_module = enclave_module_list;
    while (enclave_module) {
        if (enclave_module->module == module) {
            module_hash = enclave_module->module_hash;
            break;
        }
        enclave_module = enclave_module->next;
    }
    os_mutex_unlock(&enclave_module_list_lock);

    return module_hash;
}
#endif

static void
handle_cmd_instantiate_module(uint64 *args, uint32 argc)
{
    uint64 *args_org = args;
    EnclaveModule *enclave_module = *(EnclaveModule **)args++;
    uint32 stack_size = *(uint32 *)args++;
    uint32 heap_size = *(uint32 *)args++;
    char *error_buf = *(char **)args++;
    uint32 error_buf_size = *(uint32 *)args++;
    wasm_module_inst_t module_inst;

    bh_assert(argc == 5);

    if (!runtime_inited) {
        *(void **)args_org = NULL;
        return;
    }

    if (!(module_inst =
              wasm_runtime_instantiate(enclave_module->module, stack_size,
                                       heap_size, error_buf, error_buf_size))) {
        *(void **)args_org = NULL;
        return;
    }

    *(wasm_module_inst_t *)args_org = module_inst;

    LOG_VERBOSE("Instantiate module success.\n");
}

static void
handle_cmd_deinstantiate_module(uint64 *args, uint32 argc)
{
    wasm_module_inst_t module_inst = *(wasm_module_inst_t *)args++;

    bh_assert(argc == 1);

    if (!runtime_inited) {
        return;
    }

    wasm_runtime_deinstantiate(module_inst);

    LOG_VERBOSE("Deinstantiate module success.\n");
}

static void
handle_cmd_get_exception(uint64 *args, uint32 argc)
{
    uint64 *args_org = args;
    wasm_module_inst_t module_inst = *(wasm_module_inst_t *)args++;
    char *exception = *(char **)args++;
    uint32 exception_size = *(uint32 *)args++;
    const char *exception1;

    bh_assert(argc == 3);

    if (!runtime_inited) {
        args_org[0] = false;
        return;
    }

    if ((exception1 = wasm_runtime_get_exception(module_inst))) {
        snprintf(exception, exception_size, "%s", exception1);
        args_org[0] = true;
    }
    else {
        args_org[0] = false;
    }
}

static void
handle_cmd_exec_app_main(uint64 *args, int32 argc)
{
    wasm_module_inst_t module_inst = *(wasm_module_inst_t *)args++;
    uint32 app_argc = *(uint32 *)args++;
    char **app_argv = NULL;
    uint64 total_size;
    int32 i;

    bh_assert(argc >= 3);
    bh_assert(app_argc >= 1);

    if (!runtime_inited) {
        return;
    }

    total_size = sizeof(char *) * (app_argc > 2 ? (uint64)app_argc : 2);

    if (total_size >= UINT32_MAX
        || !(app_argv = (char **)wasm_runtime_malloc(total_size))) {
        wasm_runtime_set_exception(module_inst, "allocate memory failed.");
        return;
    }

    for (i = 0; i < app_argc; i++) {
        app_argv[i] = (char *)(uintptr_t)args[i];
    }

    wasm_application_execute_main(module_inst, app_argc - 1, app_argv + 1);

    wasm_runtime_free(app_argv);
}

static void
handle_cmd_exec_app_func(uint64 *args, int32 argc)
{
    wasm_module_inst_t module_inst = *(wasm_module_inst_t *)args++;
    char *func_name = *(char **)args++;
    uint32 app_argc = *(uint32 *)args++;
    char **app_argv = NULL;
    uint64 total_size;
    int32 i, func_name_len = strlen(func_name);

    bh_assert(argc == app_argc + 3);

    if (!runtime_inited) {
        return;
    }

    total_size = sizeof(char *) * (app_argc > 2 ? (uint64)app_argc : 2);

    if (total_size >= UINT32_MAX
        || !(app_argv = (char **)wasm_runtime_malloc(total_size))) {
        wasm_runtime_set_exception(module_inst, "allocate memory failed.");
        return;
    }

    for (i = 0; i < app_argc; i++) {
        app_argv[i] = (char *)(uintptr_t)args[i];
    }

    wasm_application_execute_func(module_inst, func_name, app_argc, app_argv);

    wasm_runtime_free(app_argv);
}

static void
handle_cmd_set_log_level(uint64 *args, uint32 argc)
{
#if WASM_ENABLE_LOG != 0
    LOG_VERBOSE("Set log verbose level to %d.\n", (int)args[0]);
    bh_log_set_verbose_level((int)args[0]);
#endif
}

#ifndef SGX_DISABLE_WASI
static void
handle_cmd_set_wasi_args(uint64 *args, int32 argc)
{
    uint64 *args_org = args;
    EnclaveModule *enclave_module = *(EnclaveModule **)args++;
    char **dir_list = *(char ***)args++;
    uint32 dir_list_size = *(uint32 *)args++;
    char **env_list = *(char ***)args++;
    uint32 env_list_size = *(uint32 *)args++;
    int stdinfd = *(int *)args++;
    int stdoutfd = *(int *)args++;
    int stderrfd = *(int *)args++;
    char **wasi_argv = *(char ***)args++;
    char *p, *p1;
    uint32 wasi_argc = *(uint32 *)args++;
    char **addr_pool_list = *(char ***)args++;
    uint32 addr_pool_list_size = *(uint32 *)args++;
    uint64 total_size = 0;
    int32 i, str_len;

    bh_assert(argc == 10);

    if (!runtime_inited) {
        *args_org = false;
        return;
    }

    total_size += sizeof(char *) * (uint64)dir_list_size
                  + sizeof(char *) * (uint64)env_list_size
                  + sizeof(char *) * (uint64)addr_pool_list_size
                  + sizeof(char *) * (uint64)wasi_argc;

    for (i = 0; i < dir_list_size; i++) {
        total_size += strlen(dir_list[i]) + 1;
    }

    for (i = 0; i < env_list_size; i++) {
        total_size += strlen(env_list[i]) + 1;
    }

    for (i = 0; i < addr_pool_list_size; i++) {
        total_size += strlen(addr_pool_list[i]) + 1;
    }

    for (i = 0; i < wasi_argc; i++) {
        total_size += strlen(wasi_argv[i]) + 1;
    }

    total_size = total_size ? total_size : 1;
    if (total_size >= UINT32_MAX
        || !(enclave_module->wasi_arg_buf = p =
                 (char *)wasm_runtime_malloc((uint32)total_size))) {
        *args_org = false;
        return;
    }

    p1 = p + sizeof(char *) * dir_list_size + sizeof(char *) * env_list_size
         + sizeof(char *) * addr_pool_list_size + sizeof(char *) * wasi_argc;

    if (dir_list_size > 0) {
        enclave_module->wasi_dir_list = (char **)p;
        enclave_module->wasi_dir_list_size = dir_list_size;
        for (i = 0; i < dir_list_size; i++) {
            enclave_module->wasi_dir_list[i] = p1;
            str_len = strlen(dir_list[i]);
            bh_memcpy_s(p1, str_len + 1, dir_list[i], str_len + 1);
            p1 += str_len + 1;
        }
        p += sizeof(char *) * dir_list_size;
    }

    if (env_list_size > 0) {
        enclave_module->wasi_env_list = (char **)p;
        enclave_module->wasi_env_list_size = env_list_size;
        for (i = 0; i < env_list_size; i++) {
            enclave_module->wasi_env_list[i] = p1;
            str_len = strlen(env_list[i]);
            bh_memcpy_s(p1, str_len + 1, env_list[i], str_len + 1);
            p1 += str_len + 1;
        }
        p += sizeof(char *) * env_list_size;
    }

    if (addr_pool_list_size > 0) {
        enclave_module->wasi_addr_pool_list = (char **)p;
        enclave_module->wasi_addr_pool_list_size = addr_pool_list_size;
        for (i = 0; i < addr_pool_list_size; i++) {
            enclave_module->wasi_addr_pool_list[i] = p1;
            str_len = strlen(addr_pool_list[i]);
            bh_memcpy_s(p1, str_len + 1, addr_pool_list[i], str_len + 1);
            p1 += str_len + 1;
        }
        p += sizeof(char *) * addr_pool_list_size;
    }

    if (wasi_argc > 0) {
        enclave_module->wasi_argv = (char **)p;
        enclave_module->wasi_argc = wasi_argc;
        for (i = 0; i < wasi_argc; i++) {
            enclave_module->wasi_argv[i] = p1;
            str_len = strlen(wasi_argv[i]);
            bh_memcpy_s(p1, str_len + 1, wasi_argv[i], str_len + 1);
            p1 += str_len + 1;
        }
        p += sizeof(char *) * wasi_argc;
    }

    wasm_runtime_set_wasi_args_ex(
        enclave_module->module, (const char **)enclave_module->wasi_dir_list,
        dir_list_size, NULL, 0, (const char **)enclave_module->wasi_env_list,
        env_list_size, enclave_module->wasi_argv, enclave_module->wasi_argc,
        (stdinfd != -1) ? stdinfd : 0, (stdoutfd != -1) ? stdoutfd : 1,
        (stderrfd != -1) ? stderrfd : 2);

    wasm_runtime_set_wasi_addr_pool(
        enclave_module->module,
        (const char **)enclave_module->wasi_addr_pool_list,
        addr_pool_list_size);

    *args_org = true;
}
#else
static void
handle_cmd_set_wasi_args(uint64 *args, int32 argc)
{
    *args = true;
}
#endif /* end of SGX_DISABLE_WASI */

static void
handle_cmd_get_version(uint64 *args, uint32 argc)
{
    uint32 major, minor, patch;
    bh_assert(argc == 3);

    wasm_runtime_get_version(&major, &minor, &patch);
    args[0] = major;
    args[1] = minor;
    args[2] = patch;
}

#if WASM_ENABLE_STATIC_PGO != 0
static void
handle_cmd_get_pgo_prof_buf_size(uint64 *args, int32 argc)
{
    wasm_module_inst_t module_inst = *(wasm_module_inst_t *)args;
    uint32 buf_len;

    bh_assert(argc == 1);

    if (!runtime_inited) {
        args[0] = 0;
        return;
    }

    buf_len = wasm_runtime_get_pgo_prof_data_size(module_inst);
    args[0] = buf_len;
}

static void
handle_cmd_get_pro_prof_buf_data(uint64 *args, int32 argc)
{
    uint64 *args_org = args;
    wasm_module_inst_t module_inst = *(wasm_module_inst_t *)args++;
    char *buf = *(char **)args++;
    uint32 len = *(uint32 *)args++;
    uint32 bytes_dumped;

    bh_assert(argc == 3);

    if (!runtime_inited) {
        args_org[0] = 0;
        return;
    }

    bytes_dumped =
        wasm_runtime_dump_pgo_prof_data_to_buf(module_inst, buf, len);
    args_org[0] = bytes_dumped;
}
#endif

void
ecall_handle_command(unsigned cmd, unsigned char *cmd_buf,
                     unsigned cmd_buf_size)
{
    uint64 *args = (uint64 *)cmd_buf;
    uint32 argc = cmd_buf_size / sizeof(uint64);

    switch (cmd) {
        case CMD_INIT_RUNTIME:
            handle_cmd_init_runtime(args, argc);
            break;
        case CMD_LOAD_MODULE:
            handle_cmd_load_module(args, argc);
            break;
        case CMD_SET_WASI_ARGS:
            handle_cmd_set_wasi_args(args, argc);
            break;
        case CMD_INSTANTIATE_MODULE:
            handle_cmd_instantiate_module(args, argc);
            break;
        case CMD_LOOKUP_FUNCTION:
            break;
        case CMD_CREATE_EXEC_ENV:
            break;
        case CMD_CALL_WASM:
            break;
        case CMD_EXEC_APP_FUNC:
            handle_cmd_exec_app_func(args, argc);
            break;
        case CMD_EXEC_APP_MAIN:
            handle_cmd_exec_app_main(args, argc);
            break;
        case CMD_GET_EXCEPTION:
            handle_cmd_get_exception(args, argc);
            break;
        case CMD_DEINSTANTIATE_MODULE:
            handle_cmd_deinstantiate_module(args, argc);
            break;
        case CMD_UNLOAD_MODULE:
            handle_cmd_unload_module(args, argc);
            break;
        case CMD_DESTROY_RUNTIME:
            handle_cmd_destroy_runtime();
            break;
        case CMD_SET_LOG_LEVEL:
            handle_cmd_set_log_level(args, argc);
            break;
        case CMD_GET_VERSION:
            handle_cmd_get_version(args, argc);
            break;
#if WASM_ENABLE_STATIC_PGO != 0
        case CMD_GET_PGO_PROF_BUF_SIZE:
            handle_cmd_get_pgo_prof_buf_size(args, argc);
            break;
        case CMD_DUMP_PGO_PROF_BUF_DATA:
            handle_cmd_get_pro_prof_buf_data(args, argc);
            break;
#endif
        default:
            LOG_ERROR("Unknown command %d\n", cmd);
            break;
    }
}

void
ecall_iwasm_main(uint8_t *wasm_file_buf, uint32_t wasm_file_size)
{
    wasm_module_t wasm_module = NULL;
    wasm_module_inst_t wasm_module_inst = NULL;
    RuntimeInitArgs init_args;
    char error_buf[128];
    const char *exception;

    /* avoid duplicated init */
    if (runtime_inited) {
        return;
    }

    os_set_print_function(enclave_print);

    memset(&init_args, 0, sizeof(RuntimeInitArgs));

#if WASM_ENABLE_GLOBAL_HEAP_POOL != 0
    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);
#else
    init_args.mem_alloc_type = Alloc_With_System_Allocator;
#endif

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        enclave_print("Init runtime environment failed.");
        enclave_print("\n");
        return;
    }

    /* load WASM module */
    if (!(wasm_module = wasm_runtime_load(wasm_file_buf, wasm_file_size,
                                          error_buf, sizeof(error_buf)))) {
        enclave_print(error_buf);
        enclave_print("\n");
        goto fail1;
    }

    /* instantiate the module */
    if (!(wasm_module_inst =
              wasm_runtime_instantiate(wasm_module, 16 * 1024, 16 * 1024,
                                       error_buf, sizeof(error_buf)))) {
        enclave_print(error_buf);
        enclave_print("\n");
        goto fail2;
    }

    /* execute the main function of wasm app */
    wasm_application_execute_main(wasm_module_inst, 0, NULL);
    if ((exception = wasm_runtime_get_exception(wasm_module_inst))) {
        enclave_print(exception);
        enclave_print("\n");
    }

    /* destroy the module instance */
    wasm_runtime_deinstantiate(wasm_module_inst);

fail2:
    /* unload the module */
    wasm_runtime_unload(wasm_module);

fail1:
    /* destroy runtime environment */
    wasm_runtime_destroy();
}

void
ecall_read_wasm_sec(uint8_t **wasm_file, uint32_t *wasm_size){
    *wasm_file = sgx_get_wasm();
    *wasm_size = sgx_get_wasm_size();
}