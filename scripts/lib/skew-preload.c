/* Gate-only clock skew: add three days so a live MIT KDC (or the client
 * AS-REP check) produces KRB5KRB_AP_ERR_SKEW. Not linked into the product.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/time.h>
#include <time.h>

static const time_t SKEW = 3 * 24 * 3600;

time_t time(time_t *tloc)
{
    static time_t (*real_time)(time_t *);
    time_t v;

    if (real_time == NULL)
        real_time = (time_t (*)(time_t *))dlsym(RTLD_NEXT, "time");
    v = real_time(NULL) + SKEW;
    if (tloc != NULL)
        *tloc = v;
    return v;
}

int gettimeofday(struct timeval *tv, void *tz)
{
    static int (*real_gtod)(struct timeval *, void *);
    int rc;

    if (real_gtod == NULL)
        real_gtod = (int (*)(struct timeval *, void *))dlsym(RTLD_NEXT, "gettimeofday");
    rc = real_gtod(tv, tz);
    if (rc == 0 && tv != NULL)
        tv->tv_sec += SKEW;
    return rc;
}

int clock_gettime(clockid_t id, struct timespec *ts)
{
    static int (*real_cgt)(clockid_t, struct timespec *);
    int rc;

    if (real_cgt == NULL)
        real_cgt = (int (*)(clockid_t, struct timespec *))dlsym(RTLD_NEXT, "clock_gettime");
    rc = real_cgt(id, ts);
    if (rc == 0 && ts != NULL &&
        (id == CLOCK_REALTIME || id == CLOCK_REALTIME_COARSE))
        ts->tv_sec += SKEW;
    return rc;
}
