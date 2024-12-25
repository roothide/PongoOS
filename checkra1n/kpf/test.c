/*
 * pongoOS - https://checkra.in
 *
 * Copyright (C) 2019-2023 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include "kpf.h"
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/loader.h>
#include <paleinfo.h>
#include <mac.h>
#include <pongo.h>
#include <xnu/xnu.h>

uint32_t offsetof_p_flags;
palerain_option_t palera1n_flags = 0;

#if defined(KPF_TEST)
extern bool test_force_rootful;

#if __has_include(<bsd/string.h>)
#include <bsd/string.h>
#endif
#endif

uint32_t* find_next_insn(uint32_t* from, uint32_t num, uint32_t insn, uint32_t mask)
{
    while(num)
    {
        if((*from & mask) == (insn & mask))
        {
            return from;
        }
        from++;
        num--;
    }
    return NULL;
}
uint32_t* find_prev_insn(uint32_t* from, uint32_t num, uint32_t insn, uint32_t mask)
{
    while(num)
    {
        if((*from & mask) == (insn & mask))
        {
            return from;
        }
        from--;
        num--;
    }
    return NULL;
}

uint32_t* follow_call(uint32_t *from)
{
    uint32_t op = *from;
    if((op & 0x7c000000) != 0x14000000)
    {
        DEVLOG("follow_call 0x%" PRIx64 " is not B or BL", xnu_ptr_to_va(from));
        return NULL;
    }
    uint32_t *target = from + sxt32(op, 26);
    if(
        (target[0] & 0x9f00001f) == 0x90000010 && // adrp x16, ...
        (target[1] & 0xffc003ff) == 0xf9400210 && // ldr x16, [x16, ...]
        target[2] == 0xd61f0200                   // br x16
    ) {
        // Stub - read pointer
        int64_t pageoff = adrp_off(target[0]);
        uint64_t page = ((uint64_t)target&(~0xfffULL)) + pageoff;
        uint64_t ptr = *(uint64_t*)(page + ((((uint64_t)target[1] >> 10) & 0xfffULL) << 3));
        target = xnu_va_to_ptr(kext_rebase_va(ptr));
    }
    DEVLOG("followed call from 0x%" PRIx64 " to 0x%" PRIx64 "", xnu_ptr_to_va(from), xnu_ptr_to_va(target));
    return target;
}

struct kernel_version gKernelVersion;
static void kpf_kernel_version_init(xnu_pf_range_t *text_const_range)
{
    const char* kernelVersionStringMarker = "@(#)VERSION: Darwin Kernel Version ";
    const char *kernelVersionString = memmem(text_const_range->cacheable_base, text_const_range->size, kernelVersionStringMarker, strlen(kernelVersionStringMarker));
    if(kernelVersionString == NULL)
    {
        kernelVersionStringMarker = "Darwin Kernel Version ";
        kernelVersionString = memmem(text_const_range->cacheable_base, text_const_range->size, kernelVersionStringMarker, strlen(kernelVersionStringMarker));
        if(kernelVersionString == NULL) panic("No kernel version string found");
    }
    gKernelVersion.kernel_version_string = kernelVersionString;
    const char *start = kernelVersionString + strlen(kernelVersionStringMarker);
    char *end = NULL;
    errno = 0;
    gKernelVersion.darwinMajor = strtoimax(start, &end, 10);
    if(errno) panic("Error parsing kernel version");
    start = end+1;
    gKernelVersion.darwinMinor = strtoimax(start, &end, 10);
    if(errno) panic("Error parsing kernel version");
    start = end+1;
    gKernelVersion.darwinRevision = strtoimax(start, &end, 10);
    if(errno) panic("Error parsing kernel version");
    start = strstr(end, "root:xnu");
    if(start) start = strchr(start + strlen("root:xnu"), '-');
    if(!start) panic("Error parsing kernel version");
    gKernelVersion.xnuMajor = strtoimax(start+1, &end, 10);
    if(errno) panic("Error parsing kernel version");
    printf("Detected Kernel version Darwin: %d.%d.%d xnu: %d\n", gKernelVersion.darwinMajor, gKernelVersion.darwinMinor, gKernelVersion.darwinRevision, gKernelVersion.xnuMajor);
}


static bool found_mach_traps = false;
uint64_t traps_mask[] =
{
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0x0000000000000000, 0xffffffffffffffff,
};
uint64_t traps_match[] =
{
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000004, 0, 0x0000000000000000, 0x0000000000000005,
};
uint64_t traps_mask_alt[] =
{
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0xffffffffffffffff,
    0xffffffffffffffff, 0, 0x0000000000000000,
};
uint64_t traps_match_alt[] =
{
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000000, 0, 0x0000000000000000,
    0x0000000000000504, 0, 0x0000000000000000,
};
bool mach_traps_common(uint64_t tfp)
{
    printf("tfp=%llx\n", tfp);
    if(found_mach_traps)
    {
        panic("mach_traps found twice!");
    }
    puts("KPF: Found mach traps");

    // for the task for pid routine we only need to patch the first branch that checks if the pid == 0
    // we just replace it with a nop
    // see vm_unix.c in xnu
    uint32_t* tfp0check = find_next_insn((uint32_t*)xnu_va_to_ptr(tfp), 0x20, 0x34000000, 0xff000000);
    if(!tfp0check)
    {
        DEVLOG("mach_traps_callback: failed to find tfp0check");
        return false;
    }

    tfp0check[0] = NOP;
    puts("KPF: Found tfp0");
    printf("tfp0check=%p\n", tfp0check);
    found_mach_traps = true;

    return true;
}
bool mach_traps_callback(struct xnu_pf_patch *patch, uint64_t *mach_traps)
{
    printf("mach_traps=%p\n", mach_traps);
    return mach_traps_common(xnu_rebase_va(mach_traps[45 * 4 + 1]));
}
bool mach_traps_alt_callback(struct xnu_pf_patch *patch, uint64_t *mach_traps)
{
    printf("mach_traps=%p\n", mach_traps);
    return mach_traps_common(xnu_rebase_va(mach_traps[45 * 3 + 1]));
}


static int kpf_compare_patches(const void *a, const void *b)
{
    kpf_patch_t *one = *(kpf_patch_t**)a,
                *two = *(kpf_patch_t**)b;
    int cmp;
    // Bundle
    cmp = one->bundle ? (two->bundle ? strcmp(one->bundle, two->bundle) : 1) : (two->bundle ? -1 : 0);
    if(cmp != 0)
    {
        return cmp;
    }
    // Segment
    cmp = strcmp(one->segment, two->segment);
    if(cmp != 0)
    {
        return cmp;
    }
    // Section
    cmp = one->section ? (two->section ? strcmp(one->section, two->section) : 1) : (two->section ? -1 : 0);
    if(cmp != 0)
    {
        return cmp;
    }
    // Granule
    return (int)one->granule - (int)two->granule;
}

kpf_component_t* const kpf_components[] = {
    // &kpf_bindfs,
    // &kpf_developer_mode,
    // &kpf_dyld,
    // &kpf_launch_constraints,
    &kpf_mach_port,
    // &kpf_nvram,
    // &kpf_proc_selfname,
    // &kpf_shellcode,
    &kpf_spawn_validate_persona,
    // &kpf_overlay,
    // &kpf_ramdisk,
    &kpf_trustcache,
    // &kpf_vfs,
    // &kpf_vm_prot,
};

static void kpf_cmd(const char *cmd, char *args)
{
    static bool kpf_didrun = false;
    if(kpf_didrun)
    {
        puts("checkra1n KPF did run already! Behavior here is undefined.\n");
    }
    kpf_didrun = true;

    uint64_t tick_0 = get_ticks();
    uint64_t tick_1;

    size_t npatches = 0;
    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        kpf_component_t *component = kpf_components[i];
        for(size_t j = 0; component->patches[j].patch; ++j)
        {
            ++npatches;
        }
    }

    kpf_patch_t **patches = malloc(npatches * sizeof(kpf_patch_t*));
    if(!patches)
    {
        panic("Failed to allocate patches array");
    }

    for(size_t i = 0, n = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        kpf_component_t *component = kpf_components[i];
        for(size_t j = 0; component->patches[j].patch; ++j)
        {
            kpf_patch_t *patch = &component->patches[j];
            if(!patch->segment)
            {
                panic("KPF component %zu, patch %zu has NULL segment", i, j);
            }
            if(patch->granule != XNU_PF_ACCESS_8BIT && patch->granule != XNU_PF_ACCESS_16BIT && patch->granule != XNU_PF_ACCESS_32BIT && patch->granule != XNU_PF_ACCESS_64BIT)
            {
                panic("KPF component %zu, patch %zu has invalid granule", i, j);
            }
            patches[n++] = patch;
        }
    }

    if (dt_node_u32(dt_get("/chosen"), "board-id", 0) == 0x02 && socnum == 0x8011) {
        if (!strstr((char*)((int64_t)gBootArgs->iOS13.CommandLine - 0x800000000 + kCacheableView), "AppleEmbeddedUSBArbitrator-force-usbdevice=")) {
            strlcat((char*)((int64_t)gBootArgs->iOS13.CommandLine - 0x800000000 + kCacheableView), " AppleEmbeddedUSBArbitrator-force-usbdevice=1", 0x270);
        }
    }

    qsort(patches, npatches, sizeof(kpf_patch_t*), kpf_compare_patches);


    struct mach_header_64* hdr = xnu_header();
    xnu_pf_range_t* text_cstring_range = xnu_pf_section(hdr, "__TEXT", "__cstring");

    xnu_pf_range_t *text_const_range = xnu_pf_section(hdr, "__TEXT", "__const");
    kpf_kernel_version_init(text_const_range);
    free(text_const_range);

    // extern struct mach_header_64* xnu_pf_get_kext_header(struct mach_header_64* kheader, const char* kext_bundle_id);


    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        kpf_component_t *component = kpf_components[i];
        if(component->init)
        {
            component->init(hdr, text_cstring_range, palera1n_flags);
        }
    }

    // shellcode_count = 0;
    // for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    // {
    //     kpf_component_t *component = kpf_components[i];
    //     if((component->shc_size != NULL) != (component->shc_emit != NULL))
    //     {
    //         panic("KPF component %zu has mismatching shc_size/shc_emit", i);
    //     }
    //     if(component->shc_size)
    //     {
    //         shellcode_count += component->shc_size();
    //     }
    // }
    // printf("shellcode_count=%d\n", shellcode_count);

    xnu_pf_patchset_t *patchset = NULL;
    for(size_t i = 0; i < npatches; ++i)
    {
        kpf_patch_t *patch = patches[i];
        if(!patchset)
        {
            patchset = xnu_pf_patchset_create(patch->granule);
        }
        patch->patch(patchset);
        if(i + 1 >= npatches || kpf_compare_patches(patches + i, patches + i + 1) != 0)
        {
            struct mach_header_64 *bundle;
            if(patch->bundle)
            {
                bundle = xnu_pf_get_kext_header(hdr, patch->bundle);
                if(!bundle)
                {
                    panic("Failed to find bundle %s", patch->bundle);
                }
            }
            else
            {
                bundle = hdr;
            }
            xnu_pf_range_t *range = patch->section ? xnu_pf_section(bundle, patch->segment, patch->section) : xnu_pf_segment(bundle, patch->segment);
            if(!range)
            {
                if(patch->section)
                {
                    panic("Failed to find section %s.%s in %s", patch->segment, patch->section, patch->bundle ? patch->bundle : "XNU");
                }
                else
                {
                    panic("Failed to find segment %s in %s", patch->segment, patch->bundle ? patch->bundle : "XNU");
                }
            }
            xnu_pf_emit(patchset);
            xnu_pf_apply(range, patchset);
            xnu_pf_patchset_destroy(patchset);
            free(range);
            patchset = NULL;
        }
    }


    // TODO
    //struct mach_header_64* accessory_header = xnu_pf_get_kext_header(hdr, "com.apple.iokit.IOAccessoryManager");

    xnu_pf_range_t* text_exec_range = xnu_pf_section(hdr, "__TEXT_EXEC", "__text");
    struct mach_header_64* first_kext = xnu_pf_get_first_kext(hdr);
    if (first_kext) {
        xnu_pf_range_t* first_kext_text_exec_range = xnu_pf_section(first_kext, "__TEXT_EXEC", "__text");

        if (first_kext_text_exec_range) {
            uint64_t text_exec_end_real;
            uint64_t text_exec_end = text_exec_end_real = ((uint64_t) (text_exec_range->va)) + text_exec_range->size;
            uint64_t first_kext_p = ((uint64_t) (first_kext_text_exec_range->va));

            if (text_exec_end > first_kext_p && first_kext_text_exec_range->va > text_exec_range->va) {
                text_exec_end = first_kext_p;
            }

            text_exec_range->size -= text_exec_end_real - text_exec_end;
        }
    }

    xnu_pf_range_t* plk_text_range = xnu_pf_section(hdr, "__PRELINK_TEXT", "__text");
    xnu_pf_range_t* data_const_range = xnu_pf_section(hdr, "__DATA_CONST", "__const");
    xnu_pf_range_t* plk_data_const_range = xnu_pf_section(hdr, "__PLK_DATA_CONST", "__data");
    xnu_pf_patchset_t* xnu_data_const_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_64BIT);

    // has_found_sbops = false;
    xnu_pf_maskmatch(xnu_data_const_patchset, "mach_traps", traps_match, traps_mask, sizeof(traps_match)/sizeof(uint64_t), false, (void*)mach_traps_callback);
    xnu_pf_maskmatch(xnu_data_const_patchset, "mach_traps_alt", traps_match_alt, traps_mask_alt, sizeof(traps_match_alt)/sizeof(uint64_t), false, (void*)mach_traps_alt_callback);
    // xnu_pf_ptr_to_data(xnu_data_const_patchset, xnu_slide_value(hdr), text_cstring_range, "Seatbelt sandbox policy", strlen("Seatbelt sandbox policy")+1, false, (void*)sb_ops_callback);
    xnu_pf_emit(xnu_data_const_patchset);
    xnu_pf_apply(data_const_range, xnu_data_const_patchset);
    xnu_pf_patchset_destroy(xnu_data_const_patchset);
    if(!found_mach_traps)
    {
        panic("Missing patch: mach_traps");
    }
    

    // uint32_t* shellcode_from = sandbox_shellcode;
    // uint32_t* shellcode_end = sandbox_shellcode_end;
    // uint32_t* shellcode_to = shellcode_area;

    // // TODO: tmp
    // shellcode_area = shellcode_to;

    // for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    // {
    //     kpf_component_t *component = kpf_components[i];
    //     if(component->shc_emit)
    //     {
    //         shellcode_area += component->shc_emit(shellcode_area);
    //     }
    // }

    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        if(kpf_components[i]->finish)
        {
            kpf_components[i]->finish(hdr, &palera1n_flags);
        }
    }

    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        if(kpf_components[i]->bootprep)
        {
            kpf_components[i]->bootprep(hdr, palera1n_flags);
        }
    }

    if(palera1n_flags & palerain_option_verbose_boot)
    {
        gBootArgs->Video.v_display = 0;
    }

    tick_1 = get_ticks();
    printf("KPF: Applied patchset in %" PRIu64 " ms\n", (tick_1 - tick_0) / TICKS_IN_1MS);
}

static void set_flags(char *args, palerain_option_t *flags, const char *name)
{
    if(args[0] != '\0')
    {
        palerain_option_t val = strtoul(args, NULL, 16);
        printf("Setting %s to 0x%016" PRIx64 "\n", name, val);
        *flags = val;
    }
    else
    {
        printf("%s: 0x%016" PRIx64 "\n", name, *flags);
    }
}

static void palera1n_flags_cmd(const char *cmd, char *args)
{
    set_flags(args, &palera1n_flags, "palera1n_flags");
}




#include <pongo.h>
bool xnu_is_slid(struct mach_header_64* header) {
    struct segment_command_64* seg = macho_get_segment(header, "__TEXT");
    if (seg->vmaddr == 0xFFFFFFF007004000ULL) return false;
    return true;
}
// NOTE: iBoot-based rebase only applies to main XNU.
//       Kexts will never ever have been rebased when Pongo runs.
static bool has_been_rebased(void) {
    static int8_t rebase_status = -1;
    // First, determine whether we've been rebased. This feels really hacky, but it correctly covers all cases:
    //
    // 1. New-style kernels rebase themselves, so this is always false.
    // 2. Old-style kernels on a live device will always have been rebased.
    // 3. Old-style kernels on kpf-test will not have been rebased, but we use a slide of 0x0 there
    //    and the pointers are valid by themselves, so they can be treated as correctly rebased.
    //
    if(rebase_status == -1)
    {
        struct segment_command_64 *seg = macho_get_segment(xnu_header(), "__TEXT");
        struct section_64 *sec = seg ? macho_get_section(seg, "__thread_starts") : NULL;
        rebase_status = (!sec || sec->size == 0) ? 1 : 0;
    }

    return rebase_status == 1;
}

static int dt_list_memmap_cb(void *a, dt_node_t *node, int depth, const char *key, void *val, size_t len)
{
    printf("memmap: %s, %llx\n", key, len);
    if(len == sizeof(struct memmap))
    {
        struct memmap* mmap = (struct memmap*)val;
        printf("addr=%p size=%llx\n", mmap->addr, mmap->size);
    }
    return 0;
}

void test()
{
    struct mach_header_64* hdr = xnu_header();
    printf("xnu_header: %p\n", hdr);
    uint64_t hdr_va = xnu_ptr_to_va(hdr);
    printf("hdr_va: %p\n", hdr_va);
    printf("gEntryPoint: %p\n", gEntryPoint);
    printf("xnu_is_slid: %d\n", xnu_is_slid(hdr));
    printf("has_been_rebased: %d\n", has_been_rebased());
    printf("xnu_slide_value: %p\n", xnu_slide_value(hdr));
    printf("kCacheableView: %p\n", kCacheableView);
    printf("gBootArgs: %p\n", gBootArgs);
    printf("gBootArgs->physBase: %p\n", gBootArgs->physBase);
    printf("gBootArgs->virtBase: %p\n", gBootArgs->virtBase);
    printf("gBootArgs->memSize: %lx\n", gBootArgs->memSize);
    printf("gBootArgs->topOfKernelData: %p\n", gBootArgs->topOfKernelData);
    printf("gTopOfKernelData: %p\n", gTopOfKernelData);
    
    dt_node_t *memory_map = dt_node(gDeviceTree, "/chosen/memory-map");
    dt_parse(memory_map, -1, NULL, NULL, NULL, &dt_list_memmap_cb, NULL);

}

void module_entry(void)
{
    puts("");
    puts("");
    puts("#==================");
    puts("#");
    puts("# checkra1n kpf " CHECKRA1N_VERSION);
    puts("#");
    puts("# Proudly written in nano");
    puts("# (c) 2019-2023 Kim Jong Cracks");
    puts("#");
    puts("# This software is not for sale");
    puts("# If you purchased this, please");
    puts("# report the seller.");
    puts("#");
    puts("# Get it for free at https://checkra.in");
    puts("#");
    puts("#====  Made by  ===");
    puts("# argp, axi0mx, danyl931, jaywalker, kirb, littlelailo, nitoTV");
    puts("# never_released, nullpixel, pimskeks, qwertyoruiop, sbingner, siguza");
    puts("#==== Thanks to ===");
    puts("# haifisch, jndok, jonseals, xerub, lilstevie, psychotea, sferrini");
    puts("# Cellebrite (ih8sn0w, cjori, ronyrus et al.)");
    puts("#==================");

    for(size_t i = 0; i < sizeof(kpf_components)/sizeof(kpf_components[0]); ++i)
    {
        kpf_component_t *component = kpf_components[i];
        if(component->pre_init)
        {
            component->pre_init();
        }
    }

    preboot_hook = kpf_cmd;
    command_register("palera1n_flags", "set flags for checkra1n userland", palera1n_flags_cmd);
    command_register("kpf", "running checkra1n-kpf without booting (use bootux afterwards)", kpf_cmd);
    // command_register("overlay", "loads an overlay disk image", kpf_overlay_cmd);
    command_register("test", "kpf test func", test);

    test();
}
const char *module_name = "checkra1n-kpf2-12.0,16.4";

struct pongo_exports exported_symbols[] =
{
    { .name = NULL, .value = NULL },
};
