FROM debian:bookworm

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    libc6-dev \
    libssl-dev \
    groff \
    libidn2-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy stub srs2.h and create empty libsrs2 (SRS not needed for vulnerability analysis)
COPY srs2.h /usr/local/include/srs2.h
RUN ar rcs /usr/local/lib/libsrs2.a && ranlib /usr/local/lib/libsrs2.a

# Create vpopmail stub library
COPY vpopmail_stub.c /tmp/vpopmail_stub.c
RUN mkdir -p /home/vpopmail/lib && \
    gcc -c /tmp/vpopmail_stub.c -o /tmp/vpopmail_stub.o && \
    ar rcs /home/vpopmail/lib/libvpopmail.a /tmp/vpopmail_stub.o

# Create required qmail users and groups
RUN groupadd -g 1001 qmail && \
    groupadd -g 1002 nofiles && \
    groupadd -g 1003 vchkpw && \
    useradd -u 1001 -g nofiles -d /var/qmail/alias -s /bin/false alias && \
    useradd -u 1002 -g nofiles -d /var/qmail -s /bin/false qmaild && \
    useradd -u 1003 -g nofiles -d /var/qmail -s /bin/false qmaill && \
    useradd -u 1005 -g nofiles -d /var/qmail -s /bin/false qmailp && \
    useradd -u 1006 -g qmail  -d /var/qmail -s /bin/false qmailq && \
    useradd -u 1007 -g qmail  -d /var/qmail -s /bin/false qmailr && \
    useradd -u 1008 -g qmail  -d /var/qmail -s /bin/false qmails && \
    useradd -u 1009 -g vchkpw -d /home/vpopmail -s /bin/false vpopmail && \
    mkdir -p /home/vpopmail/include /home/vpopmail/etc && \
    echo "/home/vpopmail/lib/libvpopmail.a" > /home/vpopmail/etc/lib_deps && \
    printf '#ifndef VPOPMAIL_H\n#define VPOPMAIL_H\n#include <pwd.h>\nstruct vqpasswd { char *pw_name; char *pw_passwd; char *pw_gecos; char *pw_dir; char *pw_shell; int pw_flags; char *pw_clear_passwd; gid_t pw_gid; uid_t pw_uid; };\n#define BOUNCE_ALL 1\n#define BOUNCE_MAIL 2\n#define NO_PASSWD_CHNG 4\nchar *vget_assign(const char *d, char *dir, int dirlen, uid_t *uid, gid_t *gid);\nint vauth_open(int x);\nvoid vclose(void);\nstruct vqpasswd *vauth_getpw(const char *u, const char *d);\nint vauth_user_exists(const char *u, const char *d);\nint valias_select(const char *u, const char *d);\nchar *valias_select_next(void);\nint count_rcpthosts(void);\nint is_distributed_domain(const char *d);\nconst char *format_maildirquota(const char *q);\n#endif\n' > /home/vpopmail/include/vpopmail.h && \
    printf '#ifndef VAUTH_H\n#define VAUTH_H\n#endif\n' > /home/vpopmail/include/vauth.h && \
    printf '#ifndef VPOPMAIL_CONFIG_H\n#define VPOPMAIL_CONFIG_H\n#endif\n' > /home/vpopmail/include/vpopmail_config.h && \
    chown -R vpopmail:vchkpw /home/vpopmail

# Create qmail directory structure
RUN mkdir -p /var/qmail

# Copy source
COPY qmail/ /usr/src/qmail/

WORKDIR /usr/src/qmail

# Build qmail
RUN make it 2>&1

# Install qmail
RUN make setup check 2>&1 || true

# Keep container running for analysis
CMD ["sleep", "infinity"]
