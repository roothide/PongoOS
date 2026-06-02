#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/syslimits.h>
#include <mach/machine.h>
#include <mach/vm_types.h>
#include <mach/kern_return.h>

#include "codesign.h"

#define KHOOK_NEW(name)   khook_new_##name
#define KHOOK_ORIG(name)  (*khook_orig_##name)
#define KSYMBOL(name)   __asm__("_ksymbol_" #name)
#define KADDR(addr)   __asm__("_kaddr_" #addr)

#if defined(DEV_BUILD) && !defined(DEV_TEST)
#define LOG(...) printf(__VA_ARGS__)
#else
#define LOG(...)
#endif

void* __shellcode_payload_data = NULL;
uint32_t __shellcode_payload_size = 0;

static const char* allowedApps[] = 
{
    "/FilzaTS.app/FilzaTS",
    "/Dopamine.app/Dopamine",
    "/Bootstrap.app/Bootstrap",
    "/TrollStore.app/TrollStore",
    "/CocoaTopTS.app/CocoaTopTS",
};

static const char* allowedIdentities[] = 
{
    "palehide.jbinit",
    "com.icraze.gtatracker", //CTBUG2
    "com.apple.Playgrounds.DocumentCheckerExtension", //Bootstrap 2.0
};

static const char* platformIdentities[] = 
{
    "palehide.jbinit",
};

static const char* allowedTeamIds[] =
{
    "T8ALTGMVXN", //CTBUG2
    "APPLECOMPUTER", //Bootstrap 2.0
};

#define CONFIG_REQUIRES_U32_MUNGING 1

#if CONFIG_REQUIRES_U32_MUNGING
#define	PAD_(t)	(sizeof(uint64_t) <= sizeof(t) \
 		? 0 : sizeof(uint64_t) - sizeof(t))
#else
#define	PAD_(t)	(sizeof(uint32_t) <= sizeof(t) \
 		? 0 : sizeof(uint32_t) - sizeof(t))
#endif

#define	PADL_(t)	0
#define	PADR_(t)	PAD_(t)

typedef u_int64_t               user_addr_t;
typedef u_int64_t               user_size_t;

enum uio_rw { UIO_READ, UIO_WRITE };
enum uio_seg {
	UIO_USERSPACE           = 0,    /* kernel address is virtual,  to/from user virtual */
	UIO_SYSSPACE            = 2,    /* kernel address is virtual,  to/from system virtual */
	UIO_USERSPACE32         = 5,    /* kernel address is virtual,  to/from user 32-bit virtual */
	UIO_USERSPACE64         = 8,    /* kernel address is virtual,  to/from user 64-bit virtual */
	UIO_SYSSPACE32          = 11    /* deprecated */
};
struct vfs_context {
	struct thread*        vc_thread;              /* pointer to Mach thread */
	struct kauth_cred*    vc_ucred;               /* per thread credential */
};
#define IO_UNIT         0x0001          /* do I/O as atomic unit */
#define IO_APPEND       0x0002          /* append write to end */
#define IO_SYNC         0x0004          /* do I/O synchronously */
#define IO_NODELOCKED   0x0008          /* underlying node already locked */

uint64_t kslide KADDR(0);

void (*panic)(const char *s, ...) KSYMBOL(panic);
void (*printf)(const char* format, ...) KSYMBOL(printf);

int (*copyin)(const user_addr_t user_addr, void *kernel_addr, size_t nbytes) KSYMBOL(copyin);
int (*copyout)(const void *kernel_addr, user_addr_t user_addr, size_t nbytes) KSYMBOL(copyout);
int (*copyinstr)(const user_addr_t user_addr, char *kernel_addr, size_t nbytes, size_t *lencopied) KSYMBOL(copyinstr);

int (*vn_getpath)(struct vnode *vp, char *pathbuf, int *len) KSYMBOL(vn_getpath);

pid_t (*proc_selfpid)(void) KSYMBOL(proc_selfpid);
pid_t (*proc_pid)(struct proc* p) KSYMBOL(proc_pid);
char* (*proc_best_name)(struct proc* p) KSYMBOL(proc_best_name);
int (*proc_csflags)(struct proc* p, uint64_t *flags) KSYMBOL(proc_csflags);

struct proc* (*current_proc)(void) KSYMBOL(current_proc);
struct task* (*current_task)(void) KSYMBOL(current_task);
struct thread* (*current_thread)(void) KSYMBOL(current_thread);
struct task* (*proc_task)(struct proc* p) KSYMBOL(proc_task);
struct proc* (*get_bsdtask_info)(struct task* t) KSYMBOL(get_bsdtask_info);
uint64_t (*thread_tid)(struct thread* thread) KSYMBOL(thread_tid);

struct cs_blob* (*csproc_get_blob)(struct proc *p) KSYMBOL(csproc_get_blob);
int (*csproc_get_platform_binary)(struct proc *p) KSYMBOL(csproc_get_platform_binary);

typedef struct __SC_GenericBlob CS_GenericBlob;
typedef struct __CodeDirectory CS_CodeDirectory;
void* (*csblob_get_addr)(struct cs_blob *blob) KSYMBOL(csblob_get_addr);
size_t (*csblob_get_size)(struct cs_blob *blob) KSYMBOL(csblob_get_size);
const char* (*csblob_get_identity)(struct cs_blob *cs_blob) KSYMBOL(csblob_get_identity);
// const CS_CodeDirectory* (*csblob_get_code_directory)(struct cs_blob *csblob) KSYMBOL(csblob_get_code_directory); //not available on ios15
const CS_GenericBlob* (*csblob_find_blob_bytes)(const uint8_t *addr, size_t length, uint32_t type, uint32_t magic) KSYMBOL(csblob_find_blob_bytes);

struct vfs_context* (*vfs_context_kernel)(void) KSYMBOL(vfs_context_kernel);
int (*vnode_close)(struct vnode* vp, int flags, struct vfs_context* ctx) KSYMBOL(vnode_close);
int (*vnode_open)(const char *path, int fmode, int cmode, int flags, struct vnode** vpp, struct vfs_context* ctx) KSYMBOL(vnode_open);
int (*vn_rdwr)(enum uio_rw rw, struct vnode *vp, caddr_t base, int len, off_t offset, enum uio_seg segflg, int ioflg, struct kauth_cred* cred, int *aresid, struct proc* p) KSYMBOL(vn_rdwr);

struct vm_map* (*get_task_map)(struct task* t) KSYMBOL(get_task_map);
kern_return_t (*mach_vm_allocate_external)(struct vm_map* map, void** addr, size_t size, int flags) KSYMBOL(mach_vm_allocate_external);
kern_return_t (*mach_vm_deallocate)(struct vm_map* map, void* addr, size_t size) KSYMBOL(mach_vm_deallocate);

static char* proc_selfname()
{
    return proc_best_name(current_proc());
}

static uint64_t thread_selftid()
{
    return thread_tid(current_thread());
}

struct __SC_GenericBlob {
	uint32_t magic;                                 /* magic number */
	uint32_t length;                                /* total length of blob */
	char data[];
}
__attribute__ ((aligned(1)));

/*
 * C form of a CodeDirectory.
 */
struct __CodeDirectory {
	uint32_t magic;                                 /* magic number (CSMAGIC_CODEDIRECTORY) */
	uint32_t length;                                /* total length of CodeDirectory blob */
	uint32_t version;                               /* compatibility version */
	uint32_t flags;                                 /* setup and mode flags */
	uint32_t hashOffset;                    /* offset of hash slot element at index zero */
	uint32_t identOffset;                   /* offset of identity string */
	uint32_t nSpecialSlots;                 /* number of special hash slots */
	uint32_t nCodeSlots;                    /* number of ordinary (code) hash slots */
	uint32_t codeLimit;                             /* limit to main image signature range */
	uint8_t hashSize;                               /* size of each hash in bytes */
	uint8_t hashType;                               /* type of hash (cdHashType* constants) */
	uint8_t platform;                               /* platform identity; zero if not platform binary */
	uint8_t pageSize;                               /* log2(page size in bytes); 0 => infinite */
	uint32_t spare2;                                /* unused (must be zero) */

	char end_earliest[0];

	/* Version 0x20100 */
	uint32_t scatterOffset;                 /* offset of optional scatter vector */
	char end_withScatter[0];

	/* Version 0x20200 */
	uint32_t teamOffset;                    /* offset of optional team identity */
	char end_withTeam[0];

	/* Version 0x20300 */
	uint32_t spare3;                                /* unused (must be zero) */
	uint64_t codeLimit64;                   /* limit to main image signature range, 64 bits */
	char end_withCodeLimit64[0];

	/* Version 0x20400 */
	uint64_t execSegBase;                   /* offset of executable segment */
	uint64_t execSegLimit;                  /* limit of executable segment */
	uint64_t execSegFlags;                  /* executable segment flags */
	char end_withExecSeg[0];

	/* Version 0x20500 */
	uint32_t runtime;
	uint32_t preEncryptOffset;
	char end_withPreEncryptOffset[0];

	/* Version 0x20600 */
	uint8_t linkageHashType;
	uint8_t linkageApplicationType;
	uint16_t linkageApplicationSubType;
	uint32_t linkageOffset;
	uint32_t linkageSize;
	char end_withLinkage[0];

	/* followed by dynamic content as located by offset fields above */
} 
__attribute__ ((aligned(1)));

#define CS_SUPPORTSTEAMID   0x20200
#define CSMAGIC_CODEDIRECTORY   0xfade0c02
#define CSSLOT_CODEDIRECTORY    0
#define CSSLOT_ALTERNATE_CODEDIRECTORIES 0x1000

#define ntohl(x) __builtin_bswap32(x)

static const CS_GenericBlob* csblob_find_blob(struct cs_blob* csblob, uint32_t type, uint32_t magic)
{
	return csblob_find_blob_bytes((const uint8_t *)csblob_get_addr(csblob), csblob_get_size(csblob), type, magic);
}

static const CS_CodeDirectory* csblob_get_code_directory(struct cs_blob *csblob)
{
    return (const CS_CodeDirectory *)csblob_find_blob(csblob, CSSLOT_CODEDIRECTORY, CSMAGIC_CODEDIRECTORY);
}

static const CS_CodeDirectory* csblob_get_alternate_code_directory(struct cs_blob *csblob)
{
    return (const CS_CodeDirectory *)csblob_find_blob(csblob, CSSLOT_ALTERNATE_CODEDIRECTORIES, CSMAGIC_CODEDIRECTORY);
}

static const char* csblob_get_teamid(struct cs_blob* csblob)
{
    const CS_CodeDirectory* cd = csblob_get_code_directory(csblob);
    if (cd == NULL) {
        return NULL;
    }

	if (ntohl(cd->version) < CS_SUPPORTSTEAMID) {
		return NULL;
	}

	if (cd->teamOffset == 0) {
		return NULL;
	}

	const char *name = ((const char *)cd) + ntohl(cd->teamOffset);

	return name;
}

static const char* csblob_get_alternate_teamid(struct cs_blob* csblob)
{
    const CS_CodeDirectory* cd = csblob_get_alternate_code_directory(csblob);
    if (cd == NULL) {
        return NULL;
    }

	if (ntohl(cd->version) < CS_SUPPORTSTEAMID) {
		return NULL;
	}

	if (cd->teamOffset == 0) {
		return NULL;
	}

	const char *name = ((const char *)cd) + ntohl(cd->teamOffset);

	return name;
}

static const char* csblob_get_alternate_identity(struct cs_blob* csblob)
{
	const CS_CodeDirectory* cd = csblob_get_alternate_code_directory(csblob);
	if (cd == NULL) {
		return NULL;
	}

	if (cd->identOffset == 0) {
		return NULL;
	}

	return ((const char *)cd) + ntohl(cd->identOffset);
}

// #define ALLOW_PLATFORMIZE_APPLE_PROCESS
// #define FORCE_PLATFORMIZE_ON_CTBUG2_DEVICE

__attribute__((noinline))
static int handle_vnode_check_signature(int error, struct vnode *vp, struct cs_blob *cs_blob, struct image_params *imgp, unsigned int *cs_flags, unsigned int *signer_type, int flags, unsigned int platform)
{
#if !defined(FORCE_PLATFORMIZE_ON_CTBUG2_DEVICE) || !defined(ALLOW_PLATFORMIZE_APPLE_PROCESS)
    if(error == 0) {
        return 0;
    }
#endif

    bool allow = false;
    bool platformize = false;

    char vn_path[PATH_MAX] = {0};
    size_t vn_pathlen = sizeof(vn_path);
    vn_getpath(vp, vn_path, &vn_pathlen);

    LOG("\nmac_vnode_check_signature(%p,%p,%p,%x,%d) error=%d path=%s\n", vp,cs_blob,imgp,flags,platform, error, vn_path);

    struct proc *p = current_proc();
    pid_t current_pid = proc_selfpid();
    if(current_pid == 1)
    {
        if(strncmp(vn_path, "/private/var/containers/Bundle/Application/", sizeof("/private/var/containers/Bundle/Application/")-1) == 0)
        {
            allow = true;
        }
    }
    else if(current_pid > 0)
    {
        uint64_t csflags=0;
        if(proc_csflags(p, &csflags)==0 && (csflags & CS_GET_TASK_ALLOW)!=0)
        {
            allow = true;
        }
        else if(csproc_get_blob(p) && csproc_get_platform_binary(p))
        {
            allow = true;
        }
    }

    if(allow)
    {
        allow = false;

        const char* identity = csblob_get_identity(cs_blob);
        if(identity)
        {
            for(int i = 0; i < sizeof(allowedIdentities) / sizeof(allowedIdentities[0]); i++)
            {
                if(strcmp(identity, allowedIdentities[i]) == 0)
                {
                    LOG("mac_vnode_check_signature: [%s] Allowing identity: %s : %s\n", proc_selfname(), identity, vn_path);
                    allow = true;
                    break;
                }
            }
        }
    }

    if(allow) 
    {
#ifdef ALLOW_PLATFORMIZE_APPLE_PROCESS
        const char* alternate_identity = csblob_get_alternate_identity(cs_blob);
        if(alternate_identity && strncmp(alternate_identity, "com.apple.", sizeof("com.apple.")-1) == 0)
        {
            LOG("mac_vnode_check_signature: [%s] Platformizing (%s): %s\n", proc_selfname(), alternate_identity, vn_path);
            platformize = true;
        }
        else
#endif
        //also bypass ipadOS17/18 library validation category checks
        if(imgp == NULL) //librariy loading
        {
            LOG("mac_vnode_check_signature: [%s] Platformizing library: %s\n", proc_selfname(), vn_path);
            platformize = true;
        }
        else // spawn/exec*
        {
            const char* identity = csblob_get_identity(cs_blob);
            if(identity)
            {
                for(int i = 0; i < sizeof(platformIdentities) / sizeof(platformIdentities[0]); i++)
                {
                    if(strcmp(identity, platformIdentities[i]) == 0)
                    {
                        LOG("mac_vnode_check_signature: [%s] Platformizing executable(%s): %s\n", proc_selfname(), identity, vn_path);
                        platformize = true;
                        break;
                    }
                }
            }
        }

        if(error != 0)
        {
            error = 0;
            *signer_type = 0; //CS_SIGNER_TYPE_UNKNOWN
            *cs_flags = CS_VALID|CS_SIGNED|CS_HARD|CS_KILL|CS_ENTITLEMENTS_VALIDATED|CS_GET_TASK_ALLOW;
        }

        if(platformize) 
        {
            *cs_flags |= CS_PLATFORM_BINARY|CS_ADHOC;
        }
    }

    return error;
}

int KHOOK_ORIG(mac_vnode_check_signature)(struct vnode *vp, struct cs_blob *cs_blob, struct image_params *imgp, unsigned int *cs_flags, unsigned int *signer_type, int flags, unsigned int platform);
int KHOOK_NEW(mac_vnode_check_signature)(struct vnode *vp, struct cs_blob *cs_blob, struct image_params *imgp, unsigned int *cs_flags, unsigned int *signer_type, int flags, unsigned int platform)
{
    int error = KHOOK_ORIG(mac_vnode_check_signature)(vp, cs_blob, imgp, cs_flags, signer_type, flags, platform);

    return handle_vnode_check_signature(error, vp, cs_blob, imgp, cs_flags, signer_type, flags, platform);
}

//bypass ipadOS18 validate_main_binary_check
typedef enum __attribute__((enum_extensibility(closed), flag_enum)) : uint8_t {
	CS_BLOB_ADD_ALLOW_MAIN_BINARY = (1 << 0),
} cs_blob_add_flags_t;
int KHOOK_ORIG(ubc_cs_blob_add)(struct vnode* vp, uint32_t platform, cpu_type_t cputype, cpu_subtype_t cpusubtype, off_t base_offset, vm_address_t *addr, vm_size_t size, struct image_params *imgp, int flags, struct cs_blob **ret_blob, cs_blob_add_flags_t csblob_add_flags);
int KHOOK_NEW(ubc_cs_blob_add)(struct vnode* vp, uint32_t platform, cpu_type_t cputype, cpu_subtype_t cpusubtype, off_t base_offset, vm_address_t *addr, vm_size_t size, struct image_params *imgp, int flags, struct cs_blob **ret_blob, cs_blob_add_flags_t csblob_add_flags)
{
    struct proc *p = current_proc();

    uint64_t csflags=0;
    if(proc_csflags(p, &csflags)==0 && (csflags & CS_GET_TASK_ALLOW)!=0)
    {
        csblob_add_flags = CS_BLOB_ADD_ALLOW_MAIN_BINARY;
    }
    else if(csproc_get_blob(p) && csproc_get_platform_binary(p))
    {
        csblob_add_flags = CS_BLOB_ADD_ALLOW_MAIN_BINARY;
    }
    return KHOOK_ORIG(ubc_cs_blob_add)(vp, platform, cputype, cpusubtype, base_offset, addr, size, imgp, flags, ret_blob, csblob_add_flags);
}

static void write_out(const char* path, void* data, size_t size)
{
    struct vnode *vp = NULL;
    struct vfs_context* ctx = vfs_context_kernel();
    int ret = vnode_open(path, (O_CREAT | FWRITE), 0755, 0, &vp, ctx);
    if(ret != 0 || !vp)
    {
        panic("vnode_open failed: %d %p\n", ret, vp);
        return;
    }
    
    ret = vn_rdwr(UIO_WRITE, vp, data, size, 0, UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, ctx->vc_ucred, NULL, current_proc());
    if(ret != 0)
    {
        panic("vn_rdwr failed: %d\n", ret);
        return;
    }
            
    ret = vnode_close(vp, FWRITE, ctx);
    if(ret != 0)
    {
        panic("vnode_close failed: %d\n", ret);
        return;
    }
}

static void generate_random_string(unsigned int seed, char *buffer, size_t length)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t charset_size = sizeof(charset) - 1;
    
    if (length == 0) {
        return;
    }

    unsigned int state = seed;
    for (size_t i = 0; i < length - 1; i++) {
        state = state * 1103515245 + 12345;
        buffer[i] = charset[(state >> 16) % charset_size];
    }

    buffer[length - 1] = '\0';
}

#define VM_FLAGS_ANYWHERE               0x00000001

#define POSIX_SPAWN_SETEXEC             0x0040
#define POSIX_SPAWN_CLOEXEC_DEFAULT     0x4000

struct _posix_spawn_args_desc_required {
	size_t attr_size;
	void* attrp;
	
	size_t file_actions_size;
	void *file_actions;

	size_t port_actions_size;
	void *port_actions;
};

struct posix_spawn_args {
	char pid_l_[PADL_(user_addr_t)]; user_addr_t pid; char pid_r_[PADR_(user_addr_t)];
	char path_l_[PADL_(user_addr_t)]; user_addr_t path; char path_r_[PADR_(user_addr_t)];
	char adesc_l_[PADL_(user_addr_t)]; user_addr_t adesc; char adesc_r_[PADR_(user_addr_t)];
	char argv_l_[PADL_(user_addr_t)]; user_addr_t argv; char argv_r_[PADR_(user_addr_t)];
	char envp_l_[PADL_(user_addr_t)]; user_addr_t envp; char envp_r_[PADR_(user_addr_t)];
};

int KHOOK_ORIG(posix_spawn)(struct proc* ap, struct posix_spawn_args *uap, int32_t *retval);

__attribute__((noinline))
static bool handle_posix_spawn(struct proc* ap, struct posix_spawn_args *uap, int32_t *retval)
{
#ifdef DEV_BUILD
{
    char path[PATH_MAX] = {0};
    LOG("\n[proc:%d] posix_spawn %s pidp=%p path=%p adesc=%p argv=%p envp=%p\n", proc_selfpid(), ({
        size_t pathlen = 0;
        if(uap->path) copyinstr(uap->path, path, PATH_MAX, &pathlen);
        path;
    }), uap->pid, uap->path, uap->adesc, uap->argv, uap->envp);
}
#endif

    // if(proc_selfpid() == 1)
    struct proc *p = current_proc();
    if(p && csproc_get_blob(p) && csproc_get_platform_binary(p))
    {
        size_t pathlen = 0;
        char path[PATH_MAX] = {0};
        if(uap->path) copyinstr(uap->path, path, PATH_MAX, &pathlen);

        // if(strcmp(path, "/System/Library/TextInput/kbd") == 0)
        // if(strcmp(path, "/System/Library/CoreServices/SpringBoard.app/SpringBoard") == 0)
        if(strcmp(path, "/System/Library/PrivateFrameworks/Pasteboard.framework/Support/pasted") == 0)
        {
            static int initialized = 0;
            if((initialized & 1) == 0)
            {
                initialized = 1;
                
                char jbinitpath[128] = {"/private/var/containers/Bundle/Application/.jbinit-"};
                unsigned int seed = (uint64_t)ap ^ (uint64_t)uap ^ (uint64_t)retval ^ (uint64_t)path;
                generate_random_string(seed, jbinitpath+strlen(jbinitpath), 10);
                LOG("jbinit path: %s\n", jbinitpath);

                LOG("shellcode payload: %p, %x\n", __shellcode_payload_data, __shellcode_payload_size);
                write_out(jbinitpath, __shellcode_payload_data, __shellcode_payload_size);

                void* useraddr = NULL;
                struct vm_map* current_map = get_task_map(current_task());
                kern_return_t kr = mach_vm_allocate_external(current_map, &useraddr, 0x4000, VM_FLAGS_ANYWHERE);
                LOG("mach_vm_allocate_external: %x %p\n", kr, useraddr);

                struct posix_spawn_args new_user_args = {
                    // .pid = (user_addr_t)((uint64_t)useraddr + 0),
                    .pid = (user_addr_t)uap->pid, //replace its pid so launchd will reclaim our process and restart the real daemon after jbinit exits
                    .path = (user_addr_t)((uint64_t)useraddr + 0x1000),
                    .adesc = (user_addr_t)((uint64_t)useraddr + 0x2000),
                    .argv = (user_addr_t)uap->argv,
                    .envp = (user_addr_t)uap->envp,
                };

                if(uap->adesc)
                {
                    //copy registered ports, bootstrap port, etc
                    struct _posix_spawn_args_desc_required new_desc = {0};
                    copyin(uap->adesc, &new_desc, sizeof(new_desc));

                    if(new_desc.attrp) {
                        short flags = 0;
                        copyin((user_addr_t)new_desc.attrp + 0, &flags, sizeof(flags));
                        LOG("posix_spawn: flags=0x%08X\n", flags);

                        flags &= POSIX_SPAWN_SETEXEC|POSIX_SPAWN_CLOEXEC_DEFAULT;

                        copyout(&flags, (user_addr_t)new_desc.attrp + 0, sizeof(flags));
                    }

                    copyout(&new_desc, new_user_args.adesc, sizeof(new_desc));
                }

                copyout(jbinitpath, new_user_args.path, strlen(jbinitpath) + 1);
                
                int uu_rval[2] = {0};
                int error = KHOOK_ORIG(posix_spawn)(ap, &new_user_args, uu_rval);
                if(error != 0)
                {
                    panic("posix_spawn failed: %d\n", error);
                }

                pid_t pid=0;
                if(new_user_args.pid) copyin(new_user_args.pid, &pid, sizeof(pid));
                LOG("spawn jbinit ret=%d pid=%d\n", error, pid);

                mach_vm_deallocate(current_map, useraddr, 0x4000);

                return true;
            }
        }
    }

    return false;
}

int KHOOK_NEW(posix_spawn)(struct proc* ap, struct posix_spawn_args *uap, int32_t *retval)
{
    if(handle_posix_spawn(ap, uap, retval))
    {
        //return sucess(0) so launchd will reclaim our process later
        return (retval[0]=0);
    }

#ifdef DEV_BUILD
    pid_t pid=0;
    bool exec = false;
    size_t pathlen = 0;
    char path[PATH_MAX] = {0};

    if(uap->path) copyinstr(uap->path, path, PATH_MAX, &pathlen);

    struct _posix_spawn_args_desc_required new_desc = {0};
    copyin(uap->adesc, &new_desc, sizeof(new_desc));
    if(new_desc.attrp) {
        short flags = 0;
        copyin((user_addr_t)new_desc.attrp + 0, &flags, sizeof(flags));
        if((flags & POSIX_SPAWN_SETEXEC) != 0) {
            exec = true;
        }
    }
#endif

    int error = KHOOK_ORIG(posix_spawn)(ap, uap, retval);

    LOG("[proc:%d] posix_spawn ret=%d exec=%d pid=%d : %s\n", proc_selfpid(), error, exec, ({
        if(error == 0) {
            if(!exec) {
                if(uap->pid) {
                    if(copyin(uap->pid, &pid, sizeof(pid)) != 0) {
                        pid = -2;
                    }
                } else {
                    pid = -3;
                }
            } else {
                pid = proc_selfpid();
            }
        };
        pid;
    }), path);
    
    return error;
}
