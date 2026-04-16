#include <stddef.h>
#include <sys/types.h>

struct vqpasswd {
  char *pw_name; char *pw_passwd; char *pw_gecos;
  char *pw_dir; char *pw_shell; int pw_flags;
  char *pw_clear_passwd; gid_t pw_gid; uid_t pw_uid;
};

char *vget_assign(const char *d, char *dir, int dirlen, uid_t *uid, gid_t *gid) { return NULL; }
int vauth_open(int x) { return 0; }
void vclose(void) { }
struct vqpasswd *vauth_getpw(const char *u, const char *d) { return NULL; }
int vauth_user_exists(const char *u, const char *d) { return 0; }
int valias_select(const char *u, const char *d) { return 0; }
char *valias_select_next(void) { return NULL; }
int count_rcpthosts(void) { return 0; }
int is_distributed_domain(const char *d) { return 0; }
const char *format_maildirquota(const char *q) { return ""; }
int vmaildir_readquota(const char *dir, const char *quota) { return 0; }
