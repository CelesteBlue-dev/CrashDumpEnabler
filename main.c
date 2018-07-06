#include <psp2kern/kernel/modulemgr.h>
#include <taihen.h>

static SceUID hookid = -1;
static tai_hook_ref_t g_parse_headers_hook;
static int parse_headers_patched(int ctx, const void *headers, size_t len, void *args) {
  int ret;
  ret = TAI_CONTINUE(int, g_parse_headers_hook, ctx, headers, len, args);
  *(uint32_t *)(args + 0xC8) = 0;
  return ret;
}

void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize args, void *argp) {
  hookid = taiHookFunctionImportForKernel(KERNEL_PID, 
                                          &g_parse_headers_hook, 
                                          "SceKernelModulemgr", 
                                          0x7ABF5135, // SceSblAuthMgrForKernel
                                          0xF3411881, 
                                          parse_headers_patched);
  return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
  if (hookid >= 0)
    taiHookReleaseForKernel(hookid, g_parse_headers_hook);
  return SCE_KERNEL_STOP_SUCCESS;
}
