#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "test_common.h"

#include "pool.c"

in_addr_t
getaddr(unsigned int flags, const char *hostname, int resolve_retry_seconds, bool *succeeded,
        struct signal_info *sig_info)
{
    if (succeeded)
    {
        *succeeded = false;
    }
    return 0;
}

bool
get_ipv6_addr(const char *hostname, struct in6_addr *network, unsigned int *netbits,
              msglvl_t msglevel)
{
    return false;
}

const char *
print_in_addr_t(in_addr_t addr, unsigned int flags, struct gc_arena *gc)
{
    return "0.0.0.0";
}

const char *
print_in6_addr(struct in6_addr addr6, unsigned int flags, struct gc_arena *gc)
{
    return "::";
}

struct in6_addr
add_in6_addr(struct in6_addr base, uint32_t add)
{
    uint32_t value = in6_addr_low32(&base) + add;
    base.s6_addr[12] = (uint8_t)(value >> 24);
    base.s6_addr[13] = (uint8_t)(value >> 16);
    base.s6_addr[14] = (uint8_t)(value >> 8);
    base.s6_addr[15] = (uint8_t)value;
    return base;
}

struct status_output *
status_open(const char *filename, const int refresh_freq, const int msglevel,
            const struct virtual_output *vout, const unsigned int flags)
{
    return NULL;
}

bool
status_trigger(struct status_output *so)
{
    return false;
}

void
status_reset(const struct status_output *so)
{
}

void
status_flush(struct status_output *so)
{
}

bool
status_close(struct status_output *so)
{
    return true;
}

void
status_printf(struct status_output *so, const char *format, ...)
{
}

bool
status_read(struct status_output *so, struct buffer *buf)
{
    return false;
}

static struct ifconfig_pool *
test_pool_init(int size)
{
    const in_addr_t start = 0x0a000000;
    const in_addr_t end = start + (in_addr_t)size - 1;
    struct in6_addr ipv6_base = IN6ADDR_ANY_INIT;

    return ifconfig_pool_init(true, IFCONFIG_POOL_INDIV, start, end, false, false, ipv6_base, 0);
}

static void
test_pool_default_release_is_immediate(void **state)
{
    struct ifconfig_pool *pool = test_pool_init(4);
    struct ifconfig_pool_stats stats;
    in_addr_t local = 0;
    in_addr_t remote = 0;

    now = 1000;
    ifconfig_pool_handle hand = ifconfig_pool_acquire(pool, &local, &remote, NULL, "alice");
    assert_int_equal(hand, 0);
    assert_true(ifconfig_pool_release(pool, hand, false));

    ifconfig_pool_get_stats(pool, &stats);
    assert_int_equal(stats.assigned, 0);
    assert_int_equal(stats.retained, 0);
    assert_int_equal(stats.free, 4);

    ifconfig_pool_free(pool);
}

static void
test_pool_reuses_address_within_retention(void **state)
{
    struct ifconfig_pool *pool = test_pool_init(4);
    struct ifconfig_pool_stats stats;
    in_addr_t local = 0;
    in_addr_t remote = 0;
    bool reused = false;
    uint64_t reconnects = 0;

    now = 2000;
    ifconfig_pool_set_retain(pool, 60);
    ifconfig_pool_handle hand =
        ifconfig_pool_acquire_ex(pool, &local, &remote, NULL, "alice", &reused, &reconnects);
    assert_int_equal(hand, 0);
    assert_false(reused);
    assert_int_equal(reconnects, 0);

    assert_true(ifconfig_pool_release(pool, hand, false));
    ifconfig_pool_get_stats(pool, &stats);
    assert_int_equal(stats.assigned, 0);
    assert_int_equal(stats.retained, 1);
    assert_int_equal(stats.free, 3);

    hand = ifconfig_pool_acquire_ex(pool, &local, &remote, NULL, "alice", &reused, &reconnects);
    assert_int_equal(hand, 0);
    assert_true(reused);
    assert_int_equal(reconnects, 1);
    assert_int_equal(remote, 0x0a000000);

    assert_true(ifconfig_pool_release(pool, hand, false));
    now += 61;
    ifconfig_pool_reap(pool);
    ifconfig_pool_get_stats(pool, &stats);
    assert_int_equal(stats.assigned, 0);
    assert_int_equal(stats.retained, 0);
    assert_int_equal(stats.free, 4);
    assert_int_equal(stats.expired_reclaims, 1);

    ifconfig_pool_free(pool);
}

static void
test_pool_reclaims_oldest_retained_when_exhausted(void **state)
{
    struct ifconfig_pool *pool = test_pool_init(10);
    struct ifconfig_pool_stats stats;
    in_addr_t local = 0;
    in_addr_t remote = 0;

    now = 3000;
    ifconfig_pool_set_retain(pool, 300);
    ifconfig_pool_handle a = ifconfig_pool_acquire(pool, &local, &remote, NULL, "a");
    ifconfig_pool_handle b = ifconfig_pool_acquire(pool, &local, &remote, NULL, "b");
    ifconfig_pool_handle c = ifconfig_pool_acquire(pool, &local, &remote, NULL, "c");
    assert_int_equal(a, 0);
    assert_int_equal(b, 1);
    assert_int_equal(c, 2);

    now = 3001;
    assert_true(ifconfig_pool_release(pool, a, false));
    now = 3002;
    assert_true(ifconfig_pool_release(pool, b, false));

    for (int i = 0; i < 7; ++i)
    {
        char cn[16];
        snprintf(cn, sizeof(cn), "fill-%d", i);
        assert_true(ifconfig_pool_acquire(pool, &local, &remote, NULL, cn) >= 0);
    }

    ifconfig_pool_handle replacement =
        ifconfig_pool_acquire(pool, &local, &remote, NULL, "replacement");
    assert_int_equal(replacement, a);
    ifconfig_pool_get_stats(pool, &stats);
    assert_int_equal(stats.lru_reclaims, 1);

    ifconfig_pool_free(pool);
}

static void
test_pool_shrinks_retention_under_pressure(void **state)
{
    struct ifconfig_pool *pool = test_pool_init(20);
    struct ifconfig_pool_stats stats;
    ifconfig_pool_handle handles[20];
    in_addr_t local = 0;
    in_addr_t remote = 0;

    now = 4000;
    ifconfig_pool_set_retain(pool, 120);
    for (int i = 0; i < 20; ++i)
    {
        char cn[16];
        snprintf(cn, sizeof(cn), "client-%d", i);
        handles[i] = ifconfig_pool_acquire(pool, &local, &remote, NULL, cn);
        assert_int_equal(handles[i], i);
    }

    assert_true(ifconfig_pool_release(pool, handles[0], false));
    ifconfig_pool_get_stats(pool, &stats);
    assert_int_equal(stats.retained, 1);
    assert_int_equal(pool->list[handles[0]].retained_until, now + 60);

    now += 61;
    ifconfig_pool_reap(pool);
    ifconfig_pool_get_stats(pool, &stats);
    assert_int_equal(stats.retained, 0);
    assert_int_equal(stats.free, 1);
    assert_int_equal(stats.expired_reclaims, 1);

    ifconfig_pool_free(pool);
}

static void
test_pool_release_by_cn_is_immediate(void **state)
{
    struct ifconfig_pool *pool = test_pool_init(2);
    struct ifconfig_pool_stats stats;
    in_addr_t local = 0;
    in_addr_t remote = 0;

    now = 5000;
    ifconfig_pool_set_retain(pool, 300);
    ifconfig_pool_handle hand =
        ifconfig_pool_acquire(pool, &local, &remote, NULL, "alice");
    assert_true(ifconfig_pool_release(pool, hand, false));

    assert_int_equal(ifconfig_pool_release_by_cn(pool, "alice"), 1);
    ifconfig_pool_get_stats(pool, &stats);
    assert_int_equal(stats.retained, 0);
    assert_int_equal(stats.free, 2);

    ifconfig_pool_free(pool);
}

static void
test_pool_active_sessions_use_distinct_addresses(void **state)
{
    struct ifconfig_pool *pool = test_pool_init(2);
    in_addr_t local = 0;
    in_addr_t remote1 = 0;
    in_addr_t remote2 = 0;

    now = 6000;
    ifconfig_pool_handle first =
        ifconfig_pool_acquire(pool, &local, &remote1, NULL, "alice");
    ifconfig_pool_handle second =
        ifconfig_pool_acquire(pool, &local, &remote2, NULL, "alice");

    assert_int_equal(first, 0);
    assert_int_equal(second, 1);
    assert_int_not_equal(remote1, remote2);
    assert_int_equal(ifconfig_pool_acquire(pool, &local, &remote2, NULL, "alice"), -1);

    ifconfig_pool_free(pool);
}

static void
test_pool_batch_reconnect_metrics(void **state)
{
    enum
    {
        CLIENTS = 100,
        NORMAL_WATERMARK = 50
    };
    struct ifconfig_pool *pool = test_pool_init(CLIENTS);
    struct ifconfig_pool_stats stats;
    char names[CLIENTS][16];
    ifconfig_pool_handle handles[CLIENTS];
    in_addr_t addresses[CLIENTS];
    in_addr_t local = 0;
    in_addr_t remote = 0;

    now = 7000;
    ifconfig_pool_set_retain(pool, 60);

    for (int i = 0; i < CLIENTS; ++i)
    {
        snprintf(names[i], sizeof(names[i]), "batch-%d", i);
        handles[i] =
            ifconfig_pool_acquire(pool, &local, &remote, NULL, names[i]);
        addresses[i] = remote;
        assert_true(handles[i] >= 0);

        if (i + 1 == NORMAL_WATERMARK)
        {
            ifconfig_pool_get_stats(pool, &stats);
            printf("POOL_METRIC normal assigned=%d retained=%d free=%d\n",
                   stats.assigned, stats.retained, stats.free);
            assert_int_equal(stats.assigned, NORMAL_WATERMARK);
            assert_int_equal(stats.retained, 0);
            assert_int_equal(stats.free, CLIENTS - NORMAL_WATERMARK);
        }
    }

    for (int i = 0; i < CLIENTS; ++i)
    {
        assert_true(ifconfig_pool_release(pool, handles[i], false));
    }
    ifconfig_pool_get_stats(pool, &stats);
    printf("POOL_METRIC batch_disconnect assigned=%d retained=%d free=%d\n",
           stats.assigned, stats.retained, stats.free);
    assert_int_equal(stats.assigned, 0);
    assert_int_equal(stats.retained, CLIENTS);
    assert_int_equal(stats.free, 0);

    now += 4;
    int changed = 0;
    for (int i = 0; i < CLIENTS; ++i)
    {
        bool reused = false;
        handles[i] = ifconfig_pool_acquire_ex(pool, &local, &remote, NULL, names[i],
                                              &reused, NULL);
        assert_true(reused);
        if (handles[i] < 0 || remote != addresses[i])
        {
            ++changed;
        }
    }

    ifconfig_pool_get_stats(pool, &stats);
    printf("POOL_METRIC batch_reconnect assigned=%d retained=%d free=%d "
           "address_changes=%d/%d rate=%.3f%% resources_available=%.1f%%\n",
           stats.assigned, stats.retained, stats.free, changed, CLIENTS,
           100.0 * changed / CLIENTS, 100.0 * (CLIENTS - changed) / CLIENTS);
    assert_int_equal(changed, 0);
    assert_int_equal(stats.assigned, CLIENTS);
    assert_int_equal(stats.retained, 0);
    assert_int_equal(stats.free, 0);

    ifconfig_pool_free(pool);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pool_default_release_is_immediate),
        cmocka_unit_test(test_pool_reuses_address_within_retention),
        cmocka_unit_test(test_pool_reclaims_oldest_retained_when_exhausted),
        cmocka_unit_test(test_pool_shrinks_retention_under_pressure),
        cmocka_unit_test(test_pool_release_by_cn_is_immediate),
        cmocka_unit_test(test_pool_active_sessions_use_distinct_addresses),
        cmocka_unit_test(test_pool_batch_reconnect_metrics),
    };

    return cmocka_run_group_tests_name("pool", tests, NULL, NULL);
}
