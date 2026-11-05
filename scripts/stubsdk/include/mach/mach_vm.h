/*
 * iOS ships exactly this, and nothing else, in <mach/mach_vm.h>:
 *
 *     #error mach_vm.h unsupported.
 *
 * Reproduced here so the stub SDK rejects the same include the real SDK
 * rejects, instead of quietly letting it through.
 */
#error mach_vm.h unsupported.
