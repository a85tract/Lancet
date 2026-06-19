/*
 * DNS packet parser fuzzer for Unbound
 *
 * OSV-2020-225: Heap-buffer-overflow in dname_pkt_compare
 * The vulnerability occurs in dname_pkt_compare when following DNS
 * compression pointers in a malformed packet without validating that
 * the pointer offset is within packet bounds.
 * OSS-Fuzz issue: 20308
 * Fix commit: f3724256 (bisection marker), actual fix: ba0f382ee
 */
#include "config.h"
#include "util/regional.h"
#include "util/module.h"
#include "util/config_file.h"
#include "iterator/iterator.h"
#include "iterator/iter_priv.h"
#include "iterator/iter_scrub.h"
#include "util/log.h"
#include "sldns/sbuffer.h"

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    static int inited = 0;
    if (!inited) {
        log_init("/dev/null", 0, NULL);
        inited = 1;
    }

    struct sldns_buffer *pkt = sldns_buffer_new(1);
    sldns_buffer_new_frm_data(pkt, (void *)buf, len);

    struct regional *reg = regional_create();

    struct msg_parse msg;
    struct edns_data edns;
    memset(&msg, 0, sizeof(struct msg_parse));
    memset(&edns, 0, sizeof(edns));

    if (parse_packet(pkt, &msg, reg) != LDNS_RCODE_NOERROR)
        goto out;

    {
        struct query_info qinfo_out;
        memset(&qinfo_out, 0, sizeof(struct query_info));
        qinfo_out.qname = (unsigned char *)"\03nic\02de";

        uint8_t *zonename = (unsigned char *)"\02de";

        struct module_env env;
        memset(&env, 0, sizeof(struct module_env));
        struct config_file cfg;
        memset(&cfg, 0, sizeof(struct config_file));
        cfg.harden_glue = 1;
        env.cfg = &cfg;

        struct iter_env ie;
        memset(&ie, 0, sizeof(struct iter_env));
        struct iter_priv priv;
        memset(&priv, 0, sizeof(struct iter_priv));
        ie.priv = &priv;

        scrub_message(pkt, &msg, &qinfo_out, zonename, reg, &env, &ie);
    }

out:
    regional_destroy(reg);
    sldns_buffer_free(pkt);
    return 0;
}
