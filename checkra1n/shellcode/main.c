#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/syslimits.h>
#include <mach/kern_return.h>

#include "codesign.h"

#define KHOOK_NEW(name)   khook_new_##name
#define KHOOK_ORIG(name)  (*khook_orig_##name)
#define KSYMBOL(name)   __asm__("ksymbol_" #name)

#if defined(DEV_BUILD) || defined(KPF_TEST)
#define LOG(...) printf(__VA_ARGS__)
#else
#define LOG(...)
#endif

void* __shellcode_payload_data = NULL;
uint32_t __shellcode_payload_size = 0;

const char* allowedApps[] = 
{
    "/FilzaTS.app/FilzaTS",
    "/Dopamine.app/Dopamine",
    "/Bootstrap.app/Bootstrap",
    "/TrollStore.app/TrollStore",
    "/CocoaTopTS.app/CocoaTopTS",
};

//identifier prefixes
const char* allowedIdentities[] = 
{
    "jbinit",
    "com.icraze.gtatracker", //CTBUG2
    "TrollStorePersistenceHelper",
    "com.apple.Playgrounds.DocumentCheckerExtension", //Bootstrap 2.0
};

const char* allowedTeamIds[] =
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


void (*panic)(const char *s, ...) KSYMBOL(panic);
void (*printf)(const char* format, ...) KSYMBOL(printf);

int (*copyin)(const user_addr_t user_addr, void *kernel_addr, size_t nbytes) KSYMBOL(copyin);
int (*copyout)(const void *kernel_addr, user_addr_t user_addr, size_t nbytes) KSYMBOL(copyout);
int (*copyinstr)(const user_addr_t user_addr, char *kernel_addr, size_t nbytes, size_t *lencopied) KSYMBOL(copyinstr);

int (*vn_getpath)(struct vnode *vp, char *pathbuf, int *len) KSYMBOL(vn_getpath);

pid_t (*proc_selfpid)(void) KSYMBOL(proc_selfpid);
void (*proc_selfname)(char * buf, int size) KSYMBOL(proc_selfname);

struct task* (*current_task)(void) KSYMBOL(current_task);
struct proc* (*current_proc)(void) KSYMBOL(current_proc);
struct thread* (*current_thread)(void) KSYMBOL(current_thread);
struct task* (*proc_task)(struct proc* p) KSYMBOL(proc_task);

void* (*csproc_get_blob)(struct proc *p) KSYMBOL(csproc_get_blob);
void* (*csproc_get_platform_binary)(struct proc *p) KSYMBOL(csproc_get_platform_binary);

const char* (*csblob_get_identity)(struct cs_blob *cs_blob) KSYMBOL(csblob_get_identity);

struct vfs_context* (*vfs_context_kernel)(void) KSYMBOL(vfs_context_kernel);
int (*vnode_close)(struct vnode* vp, int flags, struct vfs_context* ctx) KSYMBOL(vnode_close);
int (*vnode_open)(const char *path, int fmode, int cmode, int flags, struct vnode** vpp, struct vfs_context* ctx) KSYMBOL(vnode_open);
int (*vn_rdwr)(enum uio_rw rw, struct vnode *vp, caddr_t base, int len, off_t offset, enum uio_seg segflg, int ioflg, struct kauth_cred* cred, int *aresid, struct proc* p) KSYMBOL(vn_rdwr);

struct vm_map* (*get_task_map)(struct task* t) KSYMBOL(get_task_map);
kern_return_t (*mach_vm_allocate_external)(struct vm_map* map, void** addr, size_t size, int flags) KSYMBOL(mach_vm_allocate_external);
kern_return_t (*mach_vm_deallocate)(struct vm_map* map, void* addr, size_t size) KSYMBOL(mach_vm_deallocate);

bool string_has_suffix(const char *str, const char *suffix)
{
    if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}

int KHOOK_ORIG(mac_vnode_check_signature)(struct vnode *vp, struct cs_blob *cs_blob, struct image_params *imgp, unsigned int *cs_flags, unsigned int *signer_type, int flags, unsigned int platform);
int KHOOK_NEW(mac_vnode_check_signature)(struct vnode *vp, struct cs_blob *cs_blob, struct image_params *imgp, unsigned int *cs_flags, unsigned int *signer_type, int flags, unsigned int platform)
{
    int error = KHOOK_ORIG(mac_vnode_check_signature)(vp, cs_blob, imgp, cs_flags, signer_type, flags, platform);

    if(error != 0)
    {
        bool allow = false;

        pid_t current_pid = proc_selfpid();
        if(current_pid == 1)
        {
            char vn_path[MAXPATHLEN] = {0};
            size_t vn_pathlen = sizeof(vn_path);
            vn_getpath(vp, vn_path, &vn_pathlen);
            LOG("mac_vnode_check_signature(%p,%p,%p,%x,%d) error=%d identifier=%s path=%s\n", vp,cs_blob,imgp,flags,platform, error, csblob_get_identity(cs_blob), vn_path);

            if(strncmp(vn_path, "/private/var/containers/Bundle/Application/", sizeof("/private/var/containers/Bundle/Application/")-1) == 0)
            {
                for(int i = 0; i < sizeof(allowedApps) / sizeof(allowedApps[0]); i++)
                {
                    if(string_has_suffix(vn_path, allowedApps[i]))
                    {
                        LOG("mac_vnode_check_signature: Allowing file: %s\n", allowedApps[i]);
                        allow = true;
                        break;
                    }
                }

                if(!allow) {
                    const char *identifier = csblob_get_identity(cs_blob);
                    if(identifier) {
                        for(int i = 0; i < sizeof(allowedIdentities) / sizeof(allowedIdentities[0]); i++)
                        {
                            //check identifier prefix only
                            if(strncmp(identifier, allowedIdentities[i], strlen(allowedIdentities[i])) == 0)
                            {
                                LOG("mac_vnode_check_signature: Allowing identifier: %s\n", identifier);
                                allow = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        else if(current_pid > 0)
        {
            struct proc *p = current_proc();
            if(p && csproc_get_blob(p))
            {
                void *platform_binary = csproc_get_platform_binary(p);
                if(platform_binary)
                {
                    char procname[64] = {0};
                    LOG("mac_vnode_check_signature: Allowing process: %s\n", ({(void)proc_selfname(procname, sizeof(procname)); procname;}));
                    allow = true;
                }
            }
        }

        if(allow) 
        {
            error = 0;
            *signer_type = 0;
            *cs_flags = CS_SIGNED|CS_PLATFORM_BINARY|CS_KILL|CS_ADHOC|CS_VALID; //0x24000203
            *cs_flags |= CS_GET_TASK_ALLOW; //TS JIT Required
        }
    }

    return error;
}

void write_out(const char* path, void* data, size_t size)
{
    struct vnode *vp = NULL;
    struct vfs_context* ctx = vfs_context_kernel();
    int ret = vnode_open(path, (O_CREAT | FWRITE), 0755, 0, &vp, ctx);
    if(ret == EPERM) {
        //retry with current vfs context
        ret = vnode_open(path, (O_CREAT | FWRITE), 0755, 0, &vp, NULL);
    }
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

void generate_random_string(unsigned int seed, char *buffer, size_t length) {
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
int KHOOK_NEW(posix_spawn)(struct proc* ap, struct posix_spawn_args *uap, int32_t *retval)
{
    bool exec = false;
    size_t pathlen = 0;
    char path[PATH_MAX] = {0};

    LOG("[proc:%d] posix_spawn pid=%p path=%p adesc=%p argv=%p envp=%p : %s\n", proc_selfpid(), uap->pid, uap->path, uap->adesc, uap->argv, uap->envp, ({
        if(uap->path) copyinstr(uap->path, path, sizeof(path), &pathlen);
        path;
    }));

    if(proc_selfpid() == 1)
    {
        if(uap->path) copyinstr(uap->path, path, sizeof(path), &pathlen);

        if(strcmp(path, "/System/Library/CoreServices/SpringBoard.app/SpringBoard") == 0)
        {
            static int initialized = 0;
            if((initialized & 1) == 0)
            {
                initialized = 1;
                
                char jbinitpath[PATH_MAX] = {"/private/var/containers/Bundle/Application/.jbinit-"};
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
                    .pid = (user_addr_t)uap->pid, //replace its pid so launchd will reclaim our process and restart the real SpringBoard after jbinit exits
                    .path = (user_addr_t)((uint64_t)useraddr + 0x1000),
                    .adesc = (user_addr_t)((uint64_t)useraddr + 0x2000),
                    .argv = (user_addr_t)NULL,
                    .envp = (user_addr_t)NULL,
                };

                if(uap->adesc)
                {
                    //copy registered ports, bootstrap port, etc
                    struct _posix_spawn_args_desc_required new_desc = {0};
                    copyin(uap->adesc, &new_desc, sizeof(new_desc));

                    if(new_desc.attrp) {
                        short flags = 0; //0x0000460C=POSIX_SPAWN_CLOEXEC_DEFAULT|POSIX_SPAWN_SETSID|_POSIX_SPAWN_NANO_ALLOCATOR|POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETPGROUP
                        copyin((user_addr_t)new_desc.attrp + 0, &flags, sizeof(flags));
                        LOG("posix_spawn: flags=0x%08X\n", flags);
                        
                        if((flags & POSIX_SPAWN_SETEXEC) != 0) {
                            exec = true;
                        }

                        flags = 0x00004000; //POSIX_SPAWN_CLOEXEC_DEFAULT
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

                // return (retval[0]=666);
                return (retval[0]=0);
            }
        }
    }

    int error = KHOOK_ORIG(posix_spawn)(ap, uap, retval);

    pid_t pid=0;
    LOG("posix_spawn %s ret=%d pid=%d exec=%d\n", path, error, ({
        if(uap->pid && !exec) copyin(uap->pid, &pid, sizeof(pid)); //may fail if POSIX_SPAWN_SETEXEC is set
        pid;
    }), exec);

    return error;
}
