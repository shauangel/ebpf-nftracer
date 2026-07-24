#ifndef AMF_TEST_FRAMEWORK_H
#define AMF_TEST_FRAMEWORK_H

/*
 * framework.h — minimal, dependency-free test harness shared by every
 * amf/test/test_*.c file. No external test library: at this size,
 * pulling in e.g. Unity/CMocka on top of the libbpf dependency these
 * tests already require would be one more thing to install for no real
 * gain.
 */

#include <stdio.h>
#include <string.h>

static int g_checks_run = 0;
static int g_checks_failed = 0;
static const char *g_current_test = "";

#define CHECK(cond) \
    do { \
        g_checks_run++; \
        if (!(cond)) { \
            g_checks_failed++; \
            fprintf(stderr, "  FAIL [%s] %s:%d: %s\n", \
                    g_current_test, __FILE__, __LINE__, #cond); \
        } \
    } while (0)

#define CHECK_STREQ(a, b) CHECK(strcmp((a), (b)) == 0)

#define RUN_TEST(fn) \
    do { \
        g_current_test = #fn; \
        printf("  %s\n", #fn); \
        fn(); \
    } while (0)

static int test_summary(void)
{
    printf("\n%d checks, %d failed\n", g_checks_run, g_checks_failed);
    return g_checks_failed ? 1 : 0;
}

#endif /* AMF_TEST_FRAMEWORK_H */
