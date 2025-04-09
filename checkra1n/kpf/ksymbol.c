#include "kpf.h"
#include <pongo.h>
#include <xnu/xnu.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>

#define LOG(...) 

void* offset_to_ptr(struct mach_header_64* header, uint64_t offset)
{
    uint64_t section_vaddr = -1;
    uint64_t section_offset = -1;
    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 * seg = (struct segment_command_64 *)lc;
            
            if(seg->nsects > 0) {
                struct section_64* sec = (struct section_64*)((uint64_t)seg+sizeof(*seg));
                for(int j=0; j<seg->nsects; j++)
                {
                    if(offset >= sec[j].offset && offset < (sec[j].offset + sec[j].size))
                    {
                        section_vaddr = sec[j].addr;
                        section_offset = sec[j].offset;
                        break;
                    }
                }
            } else {
                if(offset >= seg->fileoff && offset < (seg->fileoff + seg->filesize))
                {
                    section_vaddr = seg->vmaddr;
                    section_offset = seg->fileoff;
                    break;
                }
            }
        }
        
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    
    if(section_vaddr == -1 || section_offset == -1)
    {
        printf("unable to get rva for offset %llx\n", offset);
        return NULL;
    }
    
    // printf("section_vaddr=%llx offset=%llx\n", section_vaddr, offset);
    return xnu_va_to_ptr(section_vaddr + (offset - section_offset));
}

uint64_t ksymbol(const char* name)
{
    struct mach_header_64* header = xnu_header();

    struct symtab_command* symtab = NULL;
    struct dysymtab_command* dysymtab = NULL;
    struct segment_command_64* linkedit_seg = NULL;

    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
        
        LOG("load command[%d] = %x\n", i, lc->cmd);
        
        switch(lc->cmd) {
                
            case LC_SYMTAB: {
                symtab = (struct symtab_command*)lc;
                LOG("symtab offset=%x count=%d strtab offset=%x size=%x\n", symtab->symoff, symtab->nsyms, symtab->stroff, symtab->strsize);
                
                break;
            }
                
            case LC_DYSYMTAB: {
                dysymtab = (struct dysymtab_command*)lc;
                LOG("dysymtab export_index=%d count=%d, import_index=%d count=%d, \n", dysymtab->iextdefsym, dysymtab->nextdefsym, dysymtab->iundefsym, dysymtab->nundefsym);
                
                break;
            }

            // case LC_SEGMENT_64: {
            //     struct segment_command_64 * seg = (struct segment_command_64 *) lc;

            //     if(strcmp(seg->segname,SEG_LINKEDIT)==0)
            //         linkedit_seg = seg;
                
            //     LOG("segment: %s file=%llx:%llx vm=%16llx:%16llx\n", seg->segname, seg->fileoff, seg->filesize, seg->vmaddr, seg->vmsize);
                
            //     struct section_64* sec = (struct section_64*)((uint64_t)seg+sizeof(*seg));
            //     for(int j=0; j<seg->nsects; j++)
            //     {
            //         LOG("section[%d] = %s/%s offset=%x vm=%16llx:%16llx\n", j, sec[j].segname, sec[j].sectname, sec[j].offset, sec[j].addr, sec[j].size);
            //     }
            //     break;
            // }
        }

        /////////
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }

    if(!symtab) {
        panic("No symtab found");
        return 0;
    }

    char* strptr = (char*)offset_to_ptr(header, symtab->stroff);
    struct nlist_64* symbols64 = (struct nlist_64*)offset_to_ptr(header, symtab->symoff);

    if(!strptr || !symbols64) {
        panic("Unable to get resolve symbols");
        return 0;
    }

    for(int i=0; i<symtab->nsyms; i++) {
        char* symstr = (char*)( strptr + symbols64[i].n_un.n_strx);
        // printf("sym[%d] type:%02x sect:%02x desc:%04x value:%llx \tstr:%x\t%s\n", i, symbols64[i].n_type, symbols64[i].n_sect, symbols64[i].n_desc, symbols64[i].n_value, symbols64[i].n_un.n_strx, symstr);
        if(strcmp(symstr, name) == 0)
        {
            LOG("found symbol %s at %llx\n", symstr, symbols64[i].n_value);
            return symbols64[i].n_value;
        }
    }

    panic("Unable to find symbol %s", name);
    return 0;
}
