#ifndef SRS2_H
#define SRS2_H

#define TRUE 1
#define FALSE 0
#define SRS_SUCCESS 0
#define SRS_ENOSENDERATINSRS 1
#define SRS_ENOTREWRITTEN 2

typedef struct {
  int maxage;
  int hashlength;
  int hashmin;
  int alwaysrewrite;
  char separator;
} srs_t;

static inline srs_t *srs_new(void) {
  static srs_t s = {0};
  return &s;
}

static inline void srs_free(srs_t *s) { (void)s; }

static inline int srs_set_secret(srs_t *s, const char *sec) {
  (void)s; (void)sec; return SRS_SUCCESS;
}

static inline int srs_add_secret(srs_t *s, const char *sec) {
  (void)s; (void)sec; return SRS_SUCCESS;
}

static inline int srs_set_alwaysrewrite(srs_t *s, int v) {
  (void)s; s->alwaysrewrite = v; return SRS_SUCCESS;
}

static inline int srs_set_separator(srs_t *s, char c) {
  (void)s; s->separator = c; return SRS_SUCCESS;
}

static inline int srs_forward(srs_t *s, char *out, int outlen, const char *addr, const char *domain) {
  (void)s; (void)out; (void)outlen; (void)addr; (void)domain;
  return SRS_ENOTREWRITTEN;
}

static inline int srs_reverse(srs_t *s, char *out, int outlen, const char *addr) {
  (void)s; (void)out; (void)outlen; (void)addr;
  return SRS_ENOTREWRITTEN;
}

static inline const char *srs_strerror(int e) {
  (void)e; return "SRS stub";
}

#endif
