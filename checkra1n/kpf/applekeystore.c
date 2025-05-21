#include "kpf.h"
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>


// Imports from shellcode.S
extern uint32_t applekeystore_hook[], applekeystore_hook_ptr[], applekeystore_hook_end[];

static bool need_applekeystore_patch = false;

static uint64_t* externalMethod_vtable_ptr = NULL;

static void kpf_applekeystore_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring, palerain_option_t palera1n_flags)
{    
    if(socnum == 0x8015) {
        need_applekeystore_patch = true;
    }
}

static void kpf_applekeystore_finish(struct mach_header_64 *hdr, palerain_option_t *palera1n_flags)
{
    if(!need_applekeystore_patch) return;

}

static bool kpf_applekeystore_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint32_t adrp = opcode_stream[0], add  = opcode_stream[1];
    char* str = (char*)(((uint64_t)(opcode_stream) & ~0xfffULL) + adrp_off(adrp) + ((add >> 10) & 0xfff));
    if(strcmp(str, "%s%s:%s%s%s%s%u:%s%u:%s operation %s(sel: %d ret: %x%s)%s\n") != 0)
    {
        return false;
    }

    if(externalMethod_vtable_ptr)
    {
        panic("kpf_applekeystore: Found twice");
    }

    uint32_t *start = find_prev_insn(opcode_stream - 1, 1000, 0xd10003ff, 0xffc003ff); // sub sp, sp, ...
    if(!start)
    {
        panic("kpf_applekeystore: Failed to find start of function");
    }

    uint64_t aks_externalMethod = xnu_ptr_to_va(start);
    printf("aps externalMethod=%p : %p\n", start, aks_externalMethod);

    struct mach_header_64 *aks = xnu_pf_get_kext_header(xnu_header(), "com.apple.driver.AppleSEPKeyStore");
    xnu_pf_range_t *aks_const = xnu_pf_section(aks, "__DATA_CONST", "__const");
    if(!aks_const) {
        aks_const = xnu_pf_section(xnu_header(), "__DATA_CONST", "__const");
    }

    for(int i=0; i<aks_const->size/sizeof(uint64_t); i++)
    {
        uint64_t* ptr = (uint64_t*)(aks_const->cacheable_base + i*sizeof(uint64_t));
        if(kext_rebase_va(*ptr) == aks_externalMethod)
        {
            printf("Found externalMethod vtable ptr %p\n", ptr);
            externalMethod_vtable_ptr = ptr;
            break;
        }
    }

    if(!externalMethod_vtable_ptr) {
        panic("kpf_applekeystore: externalMethod vtable ptr not found");
    }

    free(aks_const);

    printf("KPF: Found applekeystore\n");
    return true;
}

static void kpf_applekeystore_patches(xnu_pf_patchset_t *aks_text_exec_patchset)
{
    if(!need_applekeystore_patch) return;

    uint64_t matches[] =
    {
        0x90000000, // adrp x0, 0x...
        0x91000000, // add x0, x0, 0x...
    };
    uint64_t masks[] =
    {
        0x9f00001f,
        0xffc003ff,
    };
    xnu_pf_maskmatch(aks_text_exec_patchset, "applekeystore", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_applekeystore_callback);
}

static uint32_t kpf_applekeystore_size(void)
{
    if(!need_applekeystore_patch) return 0;

    return applekeystore_hook_end - applekeystore_hook;
}

static uint32_t kpf_applekeystore_emit(uint32_t *shellcode_area)
{
    if(!need_applekeystore_patch) return 0;

    printf("kpf_applekeystore_emit\n");

    memcpy(shellcode_area, applekeystore_hook, (uintptr_t)applekeystore_hook_end - (uintptr_t)applekeystore_hook);

    uint64_t shellcode_addr  = xnu_ptr_to_va(shellcode_area);
    uint64_t* shellcode_ptrs = (uint64_t*)(shellcode_area + (applekeystore_hook_ptr - applekeystore_hook));

    uint64_t orig_aks_externalMethod = *externalMethod_vtable_ptr;
    *externalMethod_vtable_ptr = shellcode_addr - xnu_slide_value(xnu_header());
    printf("externalMethod_vtable_ptr=%p orig=%p -> new=%p\n", externalMethod_vtable_ptr, orig_aks_externalMethod, *externalMethod_vtable_ptr);

    shellcode_ptrs[0] = kext_rebase_va(orig_aks_externalMethod);
    shellcode_ptrs[1] = ksymbol("_current_proc");
    shellcode_ptrs[2] = ksymbol("_csproc_get_blob");
    shellcode_ptrs[3] = ksymbol("_csproc_get_platform_binary");
    shellcode_ptrs[4] = ksymbol("_proc_selfpid");

    return applekeystore_hook_end - applekeystore_hook;
}

kpf_component_t kpf_applekeystore =
{
    .init = kpf_applekeystore_init,
    .shc_size = kpf_applekeystore_size,
    .shc_emit = kpf_applekeystore_emit,
    .finish = kpf_applekeystore_finish,
    .patches =
    {
        { "com.apple.driver.AppleSEPKeyStore", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_applekeystore_patches },
        {},
    },
};
