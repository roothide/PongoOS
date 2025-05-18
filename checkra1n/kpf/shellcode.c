#include "kpf.h"
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <mach-o/reloc.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>

#include "incbin.h"

INCBIN(SHELLCODE, SHELLCODE_BIN_PATH);

#if defined(DEV_BUILD) || defined(KPF_TEST)
#define LOG(...) printf(__VA_ARGS__)
#else
#define LOG(...)
#endif

static int shellcode_code_size = 0;
static void* shellcode_code_ptr = NULL;

static int shellcode_data_size = 0;
static void* shellcode_data_ptr = NULL;

struct section_64* shellcode_code_section = NULL;
struct section_64* shellcode_data_section = NULL;

struct symtab_command* shellcode_symtab = NULL;
struct dysymtab_command* shellcode_dysymtab = NULL;

static void* shellcode_code_area = NULL;
static void* shellcode_data_area = NULL;

void* shellcode_symbol_ptr(const char* name)
{
    struct mach_header_64* header = (struct mach_header_64*)gSHELLCODEData;

    struct symtab_command* symtab = shellcode_symtab;

    if(!symtab) {
        panic("No symtab found");
        return NULL;
    }

    char* strptr = (char*)((uint64_t)header + symtab->stroff);
    struct nlist_64* symbols64 = (struct nlist_64*)((uint64_t)header + symtab->symoff);

    if(!strptr || !symbols64) {
        panic("Unable to get resolve symbols");
        return NULL;
    }

    for(int i=0; i<symtab->nsyms; i++) {
        char* symstr = (char*)(strptr + symbols64[i].n_un.n_strx);
        //LOG("sym[%d] type:%02x sect:%02x desc:%04x value:%llx \tstr:%x\t%s\n", i, symbols64[i].n_type, symbols64[i].n_sect, symbols64[i].n_desc, symbols64[i].n_value, symbols64[i].n_un.n_strx, symstr);
        if(strcmp(symstr, name) == 0)
        {
            LOG("found symbol %s at %llx\n", symstr, symbols64[i].n_value);
            if(symbols64[i].n_value>=shellcode_code_section->addr && symbols64[i].n_value<shellcode_code_section->addr+shellcode_code_section->size)
            {
                if(!shellcode_data_area) {
                    panic("shellcode code area not initialized");
                }
                return (void*)((uint64_t)shellcode_code_area + symbols64[i].n_value - shellcode_code_section->addr);
            }
            else if(symbols64[i].n_value>=shellcode_data_section->addr && symbols64[i].n_value<shellcode_data_section->addr+shellcode_data_section->size)
            {
                if(!shellcode_data_area) {
                    panic("shellcode data area not initialized");
                }
                void* ptr = (void*)((uint64_t)shellcode_data_area + symbols64[i].n_value - shellcode_data_section->addr);
                LOG("%s symbol ptr = %p\n", name, ptr);
                return ptr;
            }
            else
            {
                panic("Invalid symbol value: %s -> ", name, symbols64[i].n_value);
                return 0;
            }
        }
    }

    printf("Unable to find symbol %s", name);
    return NULL;
}

bool parse_shellcode()
{
    struct mach_header_64* header = (struct mach_header_64*)gSHELLCODEData;
    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {        
        switch(lc->cmd) {
            case LC_SEGMENT_64: {
                struct segment_command_64 * seg = (struct segment_command_64 *) lc;
                struct section_64* sec = (struct section_64*)((uint64_t)seg+sizeof(*seg));
                for(int j=0; j<seg->nsects; j++)
                {
                    LOG("section[%d] = %s/%s offset=%x vm=%16llx:%16llx\n", j, sec[j].segname, sec[j].sectname, sec[j].offset, sec[j].addr, sec[j].size);

                    if(strcmp(seg->segname, "__SHELLCODE") != 0) {
                        panic("Invalid shellcode segment");
                    }

                    if(strcmp(sec[j].sectname, "__code") == 0) {
                        shellcode_code_section = &sec[j];
                        shellcode_code_ptr = (void*)((uint64_t)header + sec[j].offset);
                        shellcode_code_size = sec[j].size;
                    }
                    else if(strcmp(sec[j].sectname, "__data") == 0) {
                        shellcode_data_section = &sec[j];
                        shellcode_data_ptr = (void*)((uint64_t)header + sec[j].offset);
                        shellcode_data_size = sec[j].size;
                    }
                    else {
                        panic("Invalid shellcode section");
                    }
                }
                break;
            }
            case LC_SYMTAB: {
                shellcode_symtab = (struct symtab_command*)lc;
                LOG("symtab offset=%x count=%d strtab offset=%x size=%x\n", shellcode_symtab->symoff, shellcode_symtab->nsyms, shellcode_symtab->stroff, shellcode_symtab->strsize);
                break;
            }
            case LC_DYSYMTAB: {
                shellcode_dysymtab = (struct dysymtab_command*)lc;
                break;
            }
        }
        /////////
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }

    if(shellcode_data_size) {
        shellcode_data_area = alloc_static(shellcode_data_size);
        memcpy(shellcode_data_area, shellcode_data_ptr, shellcode_data_size);
        LOG("shellcode_data_area = %p : %p\n", shellcode_data_area, xnu_ptr_to_va(shellcode_data_area));
    }

    return shellcode_code_ptr!=NULL && shellcode_code_size>0;
}


#define arm64_trunc_page(x) ((x) & (~(0x1000 - 1)))
#define arm64_round_page(x) trunc_page((x) + (0x1000 - 1))
#define ALIGN(address, range) ((uintptr_t)address & ~((uintptr_t)range - 1))

// borrow from gdb, refer: binutils-gdb/gdb/arch/arm.h
#define submask(x) ((1L << ((x) + 1)) - 1)
#define bits(obj, st, fn) (((obj) >> (st)) & submask((fn) - (st)))
#define bit(obj, st) (((obj) >> (st)) & 1)
#define sbits(obj, st, fn) ((long)(bits(obj, st, fn) | ((long)bit(obj, fn) * ~submask(fn - st))))
static inline int decode_rd(uint32_t instr) {
  return bits(instr, 0, 4);
}
static inline int decode_rt(uint32_t instr) {
    return bits(instr, 0, 4);
}
static inline int decode_rn(uint32_t instr) {
  return bits(instr, 5, 9);
}
static inline int64_t SignExtend(unsigned long x, int M, int N) {
#if 1
  char sign_bit = bit(x, M - 1);
  unsigned long sign_mask = 0 - sign_bit;
  x |= ((sign_mask >> M) << M);
#else
  x = (long)((long)x << (N - M)) >> (N - M);
#endif
  return (int64_t)x;
}
static inline int64_t decode_immhi_immlo_offset(uint32_t instr) {
  typedef uint32_t instr_t;
  struct {
    instr_t Rd : 5;      // Destination register
    instr_t immhi : 19;  // 19-bit upper immediate
    instr_t dummy_0 : 5; // Must be 10000 == 0x10
    instr_t immlo : 2;   // 2-bit lower immediate
    instr_t op : 1;      // 0 = ADR, 1 = ADRP
  } instr_decode;

  *(instr_t *)&instr_decode = instr;

  int64_t imm = instr_decode.immlo + (instr_decode.immhi << 2);
  imm = SignExtend(imm, 2 + 19, 64);
  return imm;
}
static inline int64_t decode_immhi_immlo_zero12_offset(uint32_t instr) {
  int64_t imm = decode_immhi_immlo_offset(instr);
  imm = imm << 12;
  return imm;
}
static inline int64_t decode_imm14_offset(uint32_t instr) {
    int64_t offset;
    {
      int64_t imm14 = bits(instr, 5, 18);
      offset = (imm14 << 2);
    }
    offset = SignExtend(offset, 2 + 14, 64);
    return offset;
}
static inline int64_t decode_imm19_offset(uint32_t instr) {
    int64_t offset;
    {
      int64_t imm19 = bits(instr, 5, 23);
      offset = (imm19 << 2);
    }
    offset = SignExtend(offset, 2 + 19, 64);
    return offset;
}
//https://developer.arm.com/documentation/ddi0596/2021-12/Base-Instructions/ADD--immediate---Add--immediate--?lang=en
static inline int64_t decode_add_imm12_value(uint32_t instr)
{
    int32_t imm12 = (instr & 0x3FFC00) >> 10;
    uint8_t shift = (instr>>22) & 1;
    int64_t offset = shift ? (imm12 << 12) : imm12;
    return offset;
}

void build_shellcode()
{
    struct mach_header_64* header = (struct mach_header_64*)gSHELLCODEData;

    uint32_t* p = (uint32_t*)shellcode_code_ptr;
    while(p < (uint32_t*)((uint64_t)shellcode_code_ptr + shellcode_code_size))
    {
        uint32_t code = *p;
        uint64_t module_offset = (uint64_t)p - (uint64_t)header;
        uint32_t* real_shellcode_p = (uint32_t*)((uint64_t)shellcode_code_area + (uint64_t)p - (uint64_t)shellcode_code_ptr);

        // is ADR/ADRP
        if( (code&0x1F000000)==0x10000000 )
        {
            // is ADR reg,data ?
            if((code&0x9F000000)==0x10000000)
            {
                int rd = decode_rd(code);
                int64_t offset = decode_immhi_immlo_offset(code);
                uint64_t vaddr = shellcode_code_section->addr + (uint64_t)p-(uint64_t)shellcode_code_ptr + offset;
                
                LOG("%p/%llX:ADR rd=%d, offset=%llx, addr=%llx\n", p, module_offset, rd, offset, vaddr);

                if(vaddr<shellcode_code_section->addr || vaddr>=(shellcode_code_section->addr+shellcode_code_section->size))
                {
                    panic("unexpected ADR: %llx @ %llx", vaddr, module_offset);
                }

            }
            // is ADRP reg, data@PAGE ?
            else if((code&0x9F000000)==0x90000000)
            {
                uint32_t code2 = *(p+1);
                // is ADD reg, data@PAGE_OFF ?
                if ((code2&0xFF800000)==0x91000000)
                {
                    int rd = decode_rd(code);
                    int64_t page = decode_immhi_immlo_zero12_offset(code);
                    uint64_t vaddr = arm64_trunc_page(shellcode_code_section->addr + (uint64_t)p-(uint64_t)shellcode_code_ptr + page);

                    LOG("%p/%llX:ADRP rd=%d, page=%llx, addr=%llx\n", p, module_offset, rd, page, vaddr);
                    
                    int rd2 = decode_rd(code2);
                    int rn2 = decode_rn(code2);
                    
                    int64_t offset = decode_add_imm12_value(code2);
                    
                    vaddr += offset;
                    
                    LOG("%p/%llX:ADD rd=%d, rn=%d, offset=%llx, addr=%llx\n", p, module_offset+4, rd2, rn2, offset, vaddr);

                    uint64_t new_vaddr;
                    
                    if(vaddr>=shellcode_code_section->addr && vaddr<(shellcode_code_section->addr+shellcode_code_section->size))
                    {
                        uint64_t off = vaddr - shellcode_code_section->addr;
                        new_vaddr = xnu_ptr_to_va((uint64_t)shellcode_code_area + off);
                    }
                    else if(vaddr>=shellcode_data_section->addr && vaddr<(shellcode_data_section->addr+shellcode_data_section->size))
                    {
                        uint64_t off = vaddr - shellcode_data_section->addr;
                        new_vaddr = xnu_ptr_to_va((uint64_t)shellcode_data_area + off);

                    }
                    else {
                        panic("unexpected ADRL: %llx @ %llx", vaddr, module_offset);
                    }

                    uint64_t from_PAGE = ALIGN(xnu_ptr_to_va((uint64_t)real_shellcode_p), 0x1000);
                    uint64_t to_PAGE = ALIGN(new_vaddr, 0x1000);
                    uint64_t PAGEOFF = new_vaddr % 0x1000;
                
                    int64_t pages = to_PAGE - from_PAGE;
            
                    uint32_t immlo = (pages>>12) & 0x3;
                    uint32_t immhi = ((pages>>12) >> 2) & 0x7FFFF;
                    
                    *real_shellcode_p &= ~((0x3 << 29) | (0x7FFFF << 5));
                    *real_shellcode_p |= (immlo << 29) | (immhi << 5);

                    *(real_shellcode_p+1) &= ~(0xFFF << 10);
                    *(real_shellcode_p+1) |= (PAGEOFF << 10);

                    LOG("reloc -> 0x%llx : 0x%llx\n", pages, PAGEOFF);

                    //goto next
                    p++;
                }
            }
        }

        p++;
    }

    struct relocation_info* reloc_ptr = (struct relocation_info*)((uint64_t)header + shellcode_dysymtab->locreloff);
    for(int i=0; i<shellcode_dysymtab->nlocrel; i++)
    {
        LOG("reloc[%d]: r_type=%x r_address=%x r_symbolnum=%x r_pcrel=%x r_length=%x r_extern=%x\n", i, 
            reloc_ptr[i].r_type, reloc_ptr[i].r_address, reloc_ptr[i].r_symbolnum, reloc_ptr[i].r_pcrel, reloc_ptr[i].r_length, reloc_ptr[i].r_extern);

        if(reloc_ptr[i].r_length != 3)
        {
            panic("Unsupported reloc length %d", reloc_ptr[i].r_length);
        }

        if(reloc_ptr[i].r_type != 0) // 0 == X86_64_RELOC_UNSIGNED == GENERIC_RELOC_VANILLA ==  ARM64_RELOC_UNSIGNED
        {
            panic("Unsupported reloc type %x", reloc_ptr[i].r_type);
        }

        if(reloc_ptr[i].r_address<shellcode_data_section->addr || reloc_ptr[i].r_address>=(shellcode_data_section->addr+shellcode_data_section->size))
        {
            panic("unexpected reloc address: %x", reloc_ptr[i].r_address);
        }

        uint64_t slide;

        uint64_t* reloc = (uint64_t*)((uint64_t)shellcode_data_area + reloc_ptr[i].r_address - shellcode_data_section->addr);
        if(*reloc>=shellcode_data_section->addr && *reloc<(shellcode_data_section->addr+shellcode_data_section->size))
        {
             slide = (uint64_t)shellcode_data_area - (uint64_t)shellcode_data_section->addr;
        }
        else if(*reloc>=shellcode_code_section->addr && *reloc<(shellcode_code_section->addr+shellcode_code_section->size))
        {
             slide = (uint64_t)shellcode_code_area - (uint64_t)shellcode_code_section->addr;
        }
        else {
            panic("unexpected reloc value: %llx", *reloc);
        }

        uint64_t newvalue = *reloc + slide;
        LOG("reloc 0x%x->%p: %p->%p\n", reloc_ptr[i].r_address, reloc, *reloc, newvalue);
        *reloc = xnu_ptr_to_va(newvalue);
    }
}

struct khook {
    uint32_t* ptr;
    const char* name;
} * khook_list = NULL;
static int khook_count = 0;

void build_kernelhooks()
{
    uint32_t* hook_code_area = (uint32_t*)((uint64_t)shellcode_code_area + shellcode_code_size);
    uint64_t hook_code_area_vaddr = xnu_ptr_to_va(hook_code_area);
    LOG("hook_code_area:%p/%p\n", hook_code_area, hook_code_area_vaddr);

    for(int i=0; i<khook_count; i++)
    {
        struct khook* hook = &khook_list[i];

        uint32_t* khook_ptr = hook->ptr;
        uint64_t khook_vaddr = xnu_ptr_to_va(hook->ptr);
        LOG("build hook[%d] %s %p/%p\n", i, hook->name, khook_ptr, khook_vaddr);
        
        char* new_name = NULL;
        char* orig_name = NULL;
        asprintf(&new_name, "_new_%s", hook->name);
        asprintf(&orig_name, "_orig_%s", hook->name);
        void* hook_new_ptr = shellcode_symbol_ptr(new_name);
        void** hook_orig_ptr = shellcode_symbol_ptr(orig_name);
        if(!hook_new_ptr || !hook_orig_ptr)
        {
            panic("Failed to find hook %s or %s", new_name, orig_name);
        }

        *hook_orig_ptr = (void*)hook_code_area_vaddr;

        uint32_t code = *khook_ptr;
        LOG("original code = 0x%08X\n", code);

        int64_t new_offset = (uint64_t)hook_new_ptr - (uint64_t)khook_ptr;
        *(uint32_t*)khook_ptr = 0x14000000 | ((new_offset >> 2) & 0x03ffffff);

        *hook_code_area = code;

        uint32_t nextcode = 0;

        //relocate the patched code
        if((code & 0x7C000000) == 0x14000000) //B, BL
        {
            uint64_t dest = (uint64_t)khook_ptr + ((code & 0x03ffffff) << 2);
            int64_t new_offset = dest - (uint64_t)hook_code_area;

            *hook_code_area &= ~0x3ffffff;
            *hook_code_area |= (new_offset >> 2) & 0x03ffffff;
            LOG("new code = 0x%08X\n", *hook_code_area);
        }
        else if((code & 0x9F000000) == 0x90000000) //adrp
        {
            int64_t pageoff = decode_immhi_immlo_zero12_offset(code);
            uint64_t destpage = (khook_vaddr & (~0xfffULL)) + pageoff;
            int64_t newpageoff = destpage - (hook_code_area_vaddr & (~0xfffULL));
            LOG("pageoff = %llx newpageoff = %llx\n", pageoff, newpageoff);
    
            uint32_t immlo = (newpageoff>>12) & 0x3;
            uint32_t immhi = ((newpageoff>>12) >> 2) & 0x7FFFF;
            
            *hook_code_area &= ~((0x3 << 29) | (0x7FFFF << 5));
            *hook_code_area |= (immlo << 29) | (immhi << 5);
            LOG("new code = 0x%08X\n", *hook_code_area);
        }
        else if((code & 0x9F000000) == 0x10000000) //adr
        {
            int rd = decode_rd(code);
            int64_t offset = decode_immhi_immlo_offset(code);
            uint64_t dest_vaddr = khook_vaddr + offset;
            LOG("rd=%d dest_vaddr = %llx\n", rd, dest_vaddr);

            uint64_t from_PAGE = ALIGN(hook_code_area_vaddr, 0x1000);
            uint64_t to_PAGE = ALIGN(dest_vaddr, 0x1000);
            uint64_t PAGEOFF = dest_vaddr % 0x1000;
    
            int64_t pages = to_PAGE - from_PAGE;
            
            uint32_t immlo = (pages>>12) & 0x3;
            uint32_t immhi = ((pages>>12) >> 2) & 0x7FFFF;

            *hook_code_area = 0x90000000 | (rd << 0) | (immlo << 29) | (immhi << 5);
            LOG("new code = 0x%08X\n", *hook_code_area);

            hook_code_area++;

            *hook_code_area = 0x91000000 | (rd << 0) | (rd << 5) | (PAGEOFF << 10);
            LOG("new code = 0x%08X\n", *hook_code_area);
        }
        else if((code & 0x3B000000) == 0x18000000) //ldr/ldrsw
        {
            int opc = (code>>31) & 1;
            int wide = (code>>30) & 1;

            int rt = decode_rt(code);
            int64_t offset = decode_imm19_offset(code);

            uint64_t dest_vaddr = khook_vaddr + offset;
            LOG("rd=%c%d dest_vaddr = %llx\n", wide?'X':'W', rt, dest_vaddr);

            uint64_t from_PAGE = ALIGN(hook_code_area_vaddr, 0x1000);
            uint64_t to_PAGE = ALIGN(dest_vaddr, 0x1000);
            uint64_t PAGEOFF = dest_vaddr % 0x1000;
    
            int64_t pages = to_PAGE - from_PAGE;
            
            uint32_t immlo = (pages>>12) & 0x3;
            uint32_t immhi = ((pages>>12) >> 2) & 0x7FFFF;

            *hook_code_area = 0x90000000 | (rt << 0) | (immlo << 29) | (immhi << 5);
            LOG("new code = 0x%08X\n", *hook_code_area);

            hook_code_area++;

            uint32_t opcode = (opc==0 ? 0xB9400000 : 0xB9800000) | (code & 0x40000000);
            *hook_code_area = opcode | (rt << 0) | (rt << 5) | ((PAGEOFF>>(wide+2)) << 10);
            LOG("new code = 0x%08X\n", *hook_code_area);
        }
        else if(
            (code & 0xFE000000) == 0x54000000 //beq/bne
            || (code & 0x7E000000) == 0x34000000 //cbz/cbnz
        )
        {
            int64_t offset = decode_imm19_offset(code);
            uint64_t dest_vaddr = khook_vaddr + offset;
            LOG("dest_vaddr = %llx\n", dest_vaddr);

            *hook_code_area &= ~(0x07FFFF << 5);
            *hook_code_area |= (8 >> 2) << 5;
            LOG("new code = 0x%08X\n", *hook_code_area);

            int64_t dest_offset = dest_vaddr - (hook_code_area_vaddr + 8);
            nextcode = 0x14000000 | ((dest_offset >> 2) & 0x03ffffff);
            LOG("next code = 0x%08X\n", nextcode);
        }
        else if((code & 0x7E000000) == 0x36000000) //tbz/tbnz
        {
            int64_t offset = decode_imm14_offset(code);
            uint64_t dest_vaddr = khook_vaddr + offset;
            LOG("dest_vaddr = %llx\n", dest_vaddr);

            *hook_code_area &= ~(0x03FFFF << 5);
            *hook_code_area |= (8 >> 2) << 5;
            LOG("new code = 0x%08X\n", *hook_code_area);

            int64_t dest_offset = dest_vaddr - (hook_code_area_vaddr + 8);
            nextcode = 0x14000000 | ((dest_offset >> 2) & 0x03ffffff);
            LOG("next code = 0x%08X\n", nextcode);
        }

        hook_code_area++;
    
        int64_t orig_offset = khook_vaddr - hook_code_area_vaddr;
        *hook_code_area = 0x14000000 | ((orig_offset >> 2) & 0x03ffffff);

        hook_code_area++;

        if(nextcode != 0) {
            *hook_code_area = nextcode;
            hook_code_area++;
        }
    
        free(new_name);
        free(orig_name);
    }
    
    if(khook_list) {
        free(khook_list);
        khook_list = NULL;
    }
}

void khook_function(const char* name, uint32_t* ptr)
{
    if(shellcode_code_area) {
        panic("Cannot add hook after shellcode emit");
    }

    khook_list = realloc(khook_list, sizeof(struct khook) * (khook_count + 1));
    
    struct khook* hook = &khook_list[khook_count++];

    hook->ptr = ptr;
    hook->name = name;
}

void khook_set_addr(const char* name, uint32_t* ptr)
{
    for(int i=0; i<khook_count; i++)
    {
        struct khook* hook = &khook_list[i];
        if(strcmp(hook->name, name) == 0)
        {
            hook->ptr = ptr;
            return;
        }
    }
    panic("Cannot find hook %s", name);
}

void build_kernelsymbols()
{
    *(uint64_t*)shellcode_symbol_ptr("ksymbol_printf") = ksymbol_required("_printf");
    *(uint64_t*)shellcode_symbol_ptr("ksymbol_vn_getpath") = ksymbol_required("_vn_getpath");

    *(uint64_t*)shellcode_symbol_ptr("ksymbol_proc_selfpid") = ksymbol_required("_proc_selfpid");
    *(uint64_t*)shellcode_symbol_ptr("ksymbol_proc_selfname") = ksymbol_required("_proc_selfname");

    *(uint64_t*)shellcode_symbol_ptr("ksymbol_current_proc") = ksymbol_required("_current_proc");
    *(uint64_t*)shellcode_symbol_ptr("ksymbol_csproc_get_blob") = ksymbol_required("_csproc_get_blob");
    *(uint64_t*)shellcode_symbol_ptr("ksymbol_csproc_get_platform_binary") = ksymbol_required("_csproc_get_platform_binary");

    *(uint64_t*)shellcode_symbol_ptr("ksymbol_csblob_get_identity") = ksymbol_required("_csblob_get_identity");
}

static void kpf_shellcode_init(struct mach_header_64 *hdr, xnu_pf_range_t *cstring, palerain_option_t palera1n_flags)
{
    if(!parse_shellcode())
    {
        panic("Failed to parse shellcode macho");
    }

    //add hooks
    khook_function("mac_vnode_check_signature", NULL);
}

static void kpf_shellcode_finish(struct mach_header_64 *hdr, palerain_option_t *palera1n_flags)
{
    build_shellcode();
    build_kernelhooks();
    build_kernelsymbols();
}

static uint32_t kpf_shellcode_size(void)
{
    return shellcode_code_size + khook_count*4*3;
}

static uint32_t kpf_shellcode_emit(uint32_t *shellcode_area)
{
    printf("kpf_shellcode_emit = %p : %p\n", shellcode_area, xnu_ptr_to_va(shellcode_area));

    shellcode_code_area = shellcode_area;

    memcpy(shellcode_code_area, shellcode_code_ptr, shellcode_code_size);

    return kpf_shellcode_size();
}


static bool kpf_mac_vnode_check_signature_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    static bool found = false;

    uint32_t adrp = opcode_stream[0], add  = opcode_stream[1];
    char* str = (char*)(((uint64_t)(opcode_stream) & ~0xfffULL) + adrp_off(adrp) + ((add >> 10) & 0xfff));
    if(strncmp(str, "mac_vnode_check_signature: MAC hook returned no error, ", sizeof("mac_vnode_check_signature: MAC hook returned no error, ")-1) != 0)
    {
        return false;
    }

    if(found)
    {
        panic("mac_vnode_check_signature: Found twice");
    }

    uint32_t *start = find_prev_insn(opcode_stream - 1, 1000, 0xd10003ff, 0xffc003ff); // sub sp, sp, ...
    if(!start)
    {
        panic("mac_vnode_check_signature: Failed to find start of function");
    }

    khook_set_addr("mac_vnode_check_signature", start);

    printf("KPF: Found mac_vnode_check_signature: %p, %p\n", start, xnu_ptr_to_va(start));
    found = true;
    return true;
}

static void kpf_shellcode_patches(xnu_pf_patchset_t *text_patchset)
{
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
    xnu_pf_maskmatch(text_patchset, "mac_vnode_check_signature", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_mac_vnode_check_signature_callback);
}

kpf_component_t kpf_shellcode_roothide =
{
    .init = kpf_shellcode_init,
    .shc_size = kpf_shellcode_size,
    .shc_emit = kpf_shellcode_emit,
    .finish = kpf_shellcode_finish,
    .patches =
    {
        { NULL, "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_shellcode_patches },
        {},
    },
};
