#include "eapp.h"
#include "print.h"
#include <stdlib.h>
#include <string.h>
#include "wasm_export.h"
#include "bh_platform.h"
#include "eapp_pm_wasm.h"

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
} EnclaveModule;

typedef struct _penglai_vm_params_t {
    char func_name[MAX_FUNC_NAME_LEN];
    unsigned long stack_size;
    unsigned long heap_size;
    int log_verbose_level;
    bool is_repl_mode;
    bool alloc_with_pool;
    int max_thread_num;
    unsigned long argc;
    // uint64_t args[MAX_FUNC_ARGC];
    char args[MAX_FUNC_ARGC][MAX_FUNC_ARG_LEN];
    unsigned ecall_cmd;
    uint8_t *wasm_file_buf;
    uint32_t wasm_file_size;
    void* wasm_module;
    void* wasm_module_inst;
} penglai_vm_params_t;

typedef struct _penglai_vm_val_t {
    wasm_module_t wasm_module;
    wasm_module_inst_t wasm_module_inst;
} penglai_vm_val_t;

extern void
os_set_print_function(os_print_function_t pf);

#if WASM_ENABLE_SPEC_TEST == 0
static char global_heap_buf[10 * 1024 * 1024] = { 0 };
#else
static char global_heap_buf[100 * 1024 * 1024] = { 0 };
#endif

static void
set_error_buf(char *error_buf, uint32 error_buf_size, const char *string)
{
    if (error_buf != NULL)
        printf(error_buf, error_buf_size, "%s", string);
}

static void
handle_cmd_init_runtime(penglai_vm_params_t *vm_params)
{
    int max_thread_num = vm_params->max_thread_num;
    RuntimeInitArgs init_args;

    os_set_print_function(eapp_print);

    memset(&init_args, 0, sizeof(RuntimeInitArgs));
    init_args.max_thread_num = max_thread_num;

    if (vm_params->alloc_with_pool) {
        init_args.mem_alloc_type = Alloc_With_Pool;
        init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
        init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);
    }
    else {
        init_args.mem_alloc_type = Alloc_With_System_Allocator;
    }

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        eapp_print("Init runtime environment failed.\n");
        return ;
    }

    eapp_print("Init runtime environment success.\n");
    return ;
}

static void
handle_cmd_destroy_runtime()
{
    wasm_runtime_destroy();

    eapp_print("Destroy runtime success.\n");
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
handle_cmd_load_module(penglai_vm_params_t *vm_params, penglai_vm_val_t *vm_val)
{
    uint8_t *wasm_file_buf = vm_params->wasm_file_buf;
    uint32 wasm_file_size = vm_params->wasm_file_size;
    char error_buf[128];
    uint64 total_size = sizeof(EnclaveModule) + (uint64)wasm_file_size;

    vm_val->wasm_module = NULL;

    EnclaveModule *enclave_module;
    if (total_size >= UINT32_MAX
        || !(enclave_module = (EnclaveModule *)wasm_runtime_malloc(
                 (uint32)total_size))) {
            printf("wasm load module fail\n");
            return;
        }
    memset(enclave_module, 0, (uint32)total_size);
    enclave_module->wasm_file = (uint8 *)enclave_module + sizeof(EnclaveModule);
    memcpy(enclave_module->wasm_file, wasm_file_buf, wasm_file_size);

    if (!(vm_val->wasm_module =
            wasm_runtime_load(enclave_module->wasm_file, wasm_file_size,
                                error_buf, sizeof(error_buf)))) {
            wasm_runtime_free(enclave_module);
        return;
    }

    eapp_print("Load module success.\n");
    return;
}

static void
handle_cmd_unload_module(penglai_vm_params_t *vm_params, penglai_vm_val_t *vm_val)
{
    wasm_runtime_unload(vm_val->wasm_module);

    eapp_print("Unload module success.\n");
}

static void
handle_cmd_instantiate_module(penglai_vm_params_t *vm_params, penglai_vm_val_t *vm_val)
{
    uint32 stack_size = vm_params->stack_size;
    uint32 heap_size = vm_params->heap_size;
    char error_buf[128];

    vm_val->wasm_module_inst = NULL;

    if (!(vm_val->wasm_module_inst =
              wasm_runtime_instantiate(vm_val->wasm_module, stack_size,
                                       heap_size, error_buf, sizeof(error_buf)))) {
        eapp_print("Instantiate module failed.\n");
        wasm_runtime_unload(vm_val->wasm_module);
        wasm_runtime_destroy();
        return;
    }

    eapp_print("Instantiate module success.\n");
}

static void
handle_cmd_deinstantiate_module(penglai_vm_params_t *vm_params, penglai_vm_val_t *vm_val)
{
    wasm_module_inst_t module_inst = vm_val->wasm_module_inst;

    wasm_runtime_deinstantiate(module_inst);

    eapp_print("Deinstantiate module success.\n");
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

    if ((exception1 = wasm_runtime_get_exception(module_inst))) {
        snprintf(exception, exception_size, "%s", exception1);
        args_org[0] = true;
    }
    else {
        args_org[0] = false;
    }
}

static void
handle_cmd_exec_app_main(penglai_vm_params_t *vm_params, penglai_vm_val_t *vm_val)
{
    wasm_module_inst_t module_inst = vm_val->wasm_module_inst;
    uint32 app_argc = vm_params->argc;
    char **app_argv = NULL;
    uint64 total_size;
    int32 i;

    total_size = sizeof(char *) * (app_argc > 2 ? (uint64)app_argc : 2);

    if (total_size >= UINT32_MAX
        || !(app_argv = (char **)wasm_runtime_malloc(total_size))) {
        wasm_runtime_set_exception(module_inst, "allocate memory failed.");
        eapp_print("allocate memory failed\n");
        return;
    }

    for (i = 0; i < app_argc; i++)
        app_argv[i] = (char *)(uintptr_t)vm_params->args[i];
    // eapp_print("app_argc = %d\n", app_argc);
    
    eapp_print("app execution start!\n");
    wasm_application_execute_main(module_inst, app_argc, app_argv);

    eapp_print("app execution end!\n");

    wasm_runtime_free(app_argv);
}

static void
handle_cmd_exec_app_func(penglai_vm_params_t *vm_params, penglai_vm_val_t *vm_val)
{
    wasm_module_inst_t module_inst = vm_val->wasm_module_inst;
    char *func_name = vm_params->func_name;
    uint32 app_argc = vm_params->argc;
    char **app_argv = NULL;
    uint64 total_size;
    int32 i;

    total_size = sizeof(char *) * (app_argc > 2 ? (uint64)app_argc : 2);

    if (total_size >= UINT32_MAX
        || !(app_argv = (char **)wasm_runtime_malloc(total_size))) {
        wasm_runtime_set_exception(module_inst, "allocate memory failed.");
        return;
    }

    for (i = 0; i < app_argc; i++) {
        app_argv[i] = (char *)(uintptr_t)vm_params->args[i];
        eapp_print("app_argv:%d %s",i,app_argv[i]);
    }

    wasm_application_execute_func(module_inst, func_name, app_argc, app_argv);

    wasm_runtime_free(app_argv);

    eapp_print("app func execution end!\n");
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

void
ecall_handle_command(uint8_t *wasm_file_buf, uint32_t wasm_file_size, penglai_vm_params_t *vm_params, penglai_vm_val_t *vm_val)
{
    eapp_print("start handle command\n");

    unsigned cmd = vm_params->ecall_cmd;
    vm_params->wasm_file_buf = wasm_file_buf;
    vm_params->wasm_file_size = wasm_file_size;

    switch (cmd) {
        case CMD_INIT_RUNTIME:
            handle_cmd_init_runtime(vm_params);
            break;
        case CMD_LOAD_MODULE:
            handle_cmd_load_module(vm_params,vm_val);
            break;
        case CMD_SET_WASI_ARGS:
            // handle_cmd_set_wasi_args(args, argc);
            break;
        case CMD_INSTANTIATE_MODULE:
            handle_cmd_instantiate_module(vm_params, vm_val);
            break;
        case CMD_LOOKUP_FUNCTION:
            break;
        case CMD_CREATE_EXEC_ENV:
            break;
        case CMD_CALL_WASM:
            break;
        case CMD_EXEC_APP_FUNC:
            handle_cmd_exec_app_func(vm_params, vm_val);
            break;
        case CMD_EXEC_APP_MAIN:
            handle_cmd_exec_app_main(vm_params, vm_val);
            break;
        case CMD_GET_EXCEPTION:
            // handle_cmd_get_exception(args, argc);
            break;
        case CMD_DEINSTANTIATE_MODULE:
            handle_cmd_deinstantiate_module(vm_params, vm_val);
            break;
        case CMD_UNLOAD_MODULE:
            handle_cmd_unload_module(vm_params, vm_val);
            break;
        case CMD_DESTROY_RUNTIME:
            handle_cmd_destroy_runtime();
            break;
        case CMD_SET_LOG_LEVEL:
            // handle_cmd_set_log_level(args, argc);
            break;
        default:
            printf("Unknown command %d\n", cmd);
            break;
    }
}

void
ecall_iwasm_main(uint8_t *wasm_file_buf, uint32_t wasm_file_size, penglai_vm_params_t *vm_params)
{
    wasm_module_t wasm_module = NULL;
    wasm_module_inst_t wasm_module_inst = NULL;
    RuntimeInitArgs init_args;
    char error_buf[128];
    const char *exception;
    
    os_set_print_function(eapp_print);

    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    init_args.max_thread_num = vm_params->max_thread_num;
    if (vm_params->alloc_with_pool) {
        init_args.mem_alloc_type = Alloc_With_Pool;
        init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
        init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);
    } else {
        init_args.mem_alloc_type = Alloc_With_System_Allocator;
    }

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        os_printf("Init runtime environment failed.");
        os_printf("\n");
        return;
    }

    unsigned long total_size = sizeof(EnclaveModule) + (unsigned long)wasm_file_size;
    EnclaveModule *enclave_module;
    if (total_size >= UINT32_MAX
        || !(enclave_module = (EnclaveModule *)wasm_runtime_malloc(
                    (uint32)total_size))) {
        return;
    }
    memset(enclave_module, 0, (uint32)total_size);
    enclave_module->wasm_file = (unsigned char *)enclave_module + sizeof(EnclaveModule);
    memcpy(enclave_module->wasm_file, wasm_file_buf, wasm_file_size);

    /* load WASM module */
    if (!(wasm_module = wasm_runtime_load(enclave_module->wasm_file, wasm_file_size,
                                          error_buf, sizeof(error_buf)))) {
        os_printf(error_buf);
        os_printf("\n");
        goto fail1;
    }

    /* instantiate the module */
    if (!(wasm_module_inst =
              wasm_runtime_instantiate(wasm_module, vm_params->stack_size, vm_params->heap_size,
                                       error_buf, sizeof(error_buf)))) {
        os_printf(error_buf);
        os_printf("\n");
        goto fail2;
    }

    /* execute the main function of wasm app */
    unsigned long app_argc = vm_params->argc;
    char **app_argv = NULL;
    int func_name_len = strlen(vm_params->func_name);
    unsigned long params_total_size = sizeof(char *) * (app_argc);
    int i;
    if (total_size >= UINT32_MAX
        || !(app_argv = (char **)wasm_runtime_malloc(params_total_size))) {
        wasm_runtime_set_exception(wasm_module_inst, "allocate memory failed.");
        return;
    }
    for (i = 0; i < app_argc; i++)
        app_argv[i] = (char *)(uintptr_t)vm_params->args[i];
    if (func_name_len > 0)
        wasm_application_execute_func(wasm_module_inst, vm_params->func_name, app_argc, app_argv);
    else
        wasm_application_execute_main(wasm_module_inst, app_argc, app_argv);
    if ((exception = wasm_runtime_get_exception(wasm_module_inst))) {
        printf(exception);
        printf("\n");
    }
    /* destroy the module instance */
    wasm_runtime_deinstantiate(wasm_module_inst);

fail2:
    /* unload the module */
    wasm_runtime_unload(wasm_module);

fail1:
    /* destroy runtime environment */
    wasm_runtime_free(enclave_module);
    wasm_runtime_destroy();
}


int hello(unsigned long * args)
{
    // Get vm params from relay page
    penglai_vm_params_t *vm_params = (penglai_vm_params_t *)args[13];
    unsigned relay_page_size = (unsigned long) args[14];
    uint8_t *wasm_buf = penglai_get_wasm_buf_addr();
    uint32_t wasm_file_buf_len = penglai_get_wasm_buf_size();

    printf("raw: addr: %p, size: %d --\n", wasm_buf, wasm_file_buf_len);

    printf("defined: %p, %p\n", PENGLAI_WASM_EX_SEC_ADDR, PENGLAI_WASM_SEC_ADDR);

    uint8_t *sec_addr = penglai_get_wasm_sec_addr();
    uint8_t *ex_sec_addr = penglai_get_wasm_ex_sec_addr();
    uint32_t new_size = penglai_get_wasm_size();
    uint8_t *wasm_addr = penglai_get_wasm();
    printf("new: sec_addr: %p, ex_sec_addr: %p, size:%d, wasm_addr:%p", sec_addr, ex_sec_addr, new_size, wasm_addr);
    wasm_file_buf_len = new_size;
    wasm_buf = wasm_addr;



    penglai_vm_val_t vm_val;

    ecall_handle_command(wasm_buf, wasm_file_buf_len, vm_params, &vm_val);
    eapp_return_relay_page();

    vm_params = (penglai_vm_params_t *)args[13];
    relay_page_size = (unsigned long) args[14];

    while(vm_params->ecall_cmd != CMD_EXIT){
        ecall_handle_command(wasm_buf, wasm_file_buf_len, vm_params, &vm_val);
        eapp_return_relay_page();

        vm_params = (penglai_vm_params_t *)args[13];
        relay_page_size = (unsigned long) args[14];
    }

    EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
    unsigned long * args;
    EAPP_RESERVE_REG;
    hello(args);
}
