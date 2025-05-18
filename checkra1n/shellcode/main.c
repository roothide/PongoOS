#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/syslimits.h>

#include "codesign.h"

#define KHOOK_NEW(name)   new_##name
#define KHOOK_ORIG(name)  (*orig_##name)
#define KSYMBOL(name)   __asm__("ksymbol_" #name)

#if defined(DEV_BUILD) || defined(KPF_TEST)
#define LOG(...) printf(__VA_ARGS__)
#else
#define LOG(...)
#endif

void (*printf)(const char* format, ...) KSYMBOL(printf);
int (*vn_getpath)(struct vnode *vp, char *pathbuf, int *len) KSYMBOL(vn_getpath);

pid_t (*proc_selfpid)(void) KSYMBOL(proc_selfpid);
void (*proc_selfname)(char * buf, int size) KSYMBOL(proc_selfname);

struct proc* (*current_proc)(void) KSYMBOL(current_proc);
void* (*csproc_get_blob)(struct proc *p) KSYMBOL(csproc_get_blob);
void* (*csproc_get_platform_binary)(struct proc *p) KSYMBOL(csproc_get_platform_binary);

const char* (*csblob_get_identity)(struct cs_blob *cs_blob) KSYMBOL(csblob_get_identity);

const char* allowedApps[] = {
    "/TrollStore.app/TrollStore",
    "/Dopamine.app/Dopamine",
    "/FilzaTS.app/FilzaTS",
    "/CocoaTopTS.app/CocoaTopTS",
};

#define TROLLSTORE_DEFAULT_TEAMID   "T8ALTGMVXN"

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

            for(size_t i = 0; i < sizeof(allowedApps) / sizeof(allowedApps[0]); i++)
            {
                if(string_has_suffix(vn_path, allowedApps[i]))
                {
                    LOG("mac_vnode_check_signature: Allowing file: %s\n", allowedApps[i]);
                    allow = true;
                    break;
                }
            }

            if(!allow) {
                if(strncmp(vn_path, "/private/var/containers/Bundle/Application/", sizeof("/private/var/containers/Bundle/Application/")-1) == 0)
                {
                    const char *identifier = csblob_get_identity(cs_blob);
                    if(identifier) {
                        if(strcmp(identifier,"com.icraze.gtatracker")==0 || strncmp(identifier, "TrollStorePersistenceHelper", sizeof("TrollStorePersistenceHelper")-1) == 0)
                        {
                            LOG("mac_vnode_check_signature: Allowing identifier: %s\n", identifier);
                            allow = true;
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

        if(allow) {
            error = 0;
            *signer_type = 0;
            *cs_flags = CS_SIGNED|CS_PLATFORM_BINARY|CS_KILL|CS_ADHOC|CS_VALID; //0x24000203
        }
    }

    return error;
}
