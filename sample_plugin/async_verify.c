#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "openssl/ssl.h"
#include "ts/ts.h"

static int
cert_callback(TSCont contp, TSEvent event, void *edata)
{
    TSReleaseAssert(event == TS_EVENT_TIMEOUT);
    TSVConn vc = (TSVConn) TSContDataGet(contp);
    SSL *ssl = (SSL *)TSVConnSSLConnectionGet(vc);

    TSDebug("async_verify", "Scheduled callback called for vc=%p, resuming SSL handshake.", vc);

    SSL_set_verify_result(ssl, X509_V_OK);
    TSVConnReenable(vc);
    
    TSContDestroy(contp);
    return 0;
}


static int
verify_callback(TSCont contp, TSEvent event, void *edata)
{
    TSVConn vc = (TSVConn) edata;
    TSHttpTxn txnp = TSVConnGetHttpTxn(vc);
    TSDebug("async_verify", "Verification callback called, event=%d, vc=%p, txnp=%p", 
            event, (void *)vc, (void *)txnp);
    long verify_result = X509_V_OK;
    bool defer = false;

    SSL *ssl = (SSL *)TSVConnSSLConnectionGet(vc);

    STACK_OF(X509) *cert_chain = SSL_get_peer_cert_chain(ssl);
    if (cert_chain) {
        X509 *cert;
        int i;
        char buf[512];
        
        for (i = 0; i < sk_X509_num(cert_chain); i++) {
            cert = sk_X509_value(cert_chain, i);

            TSDebug("async_verify", "Server certificate[%d]: %s", i,
                    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf)));

            if (strstr(buf, "Google")) {
                TSDebug("async_verify", "GOOGLE! We reject the certificate.");
                verify_result = X509_V_ERR_CERT_REJECTED;
            } else if (strstr(buf, "Facebook")) {
                TSDebug("async_verify", "FACEBOOK! We accept the certificate.");
            } else if (strstr(buf, "Twitter")) {
                TSDebug("async_verify", "TWITTER! Scheduling deferred REJECT.");
                defer = true;
            }
        }
    } else {
        TSDebug("async_verify", "No server certificate!");
    }

    if (!defer) {
        SSL_set_verify_result(ssl, verify_result);
        TSVConnReenable(vc);
    } else {
        // NOTE: This is for scheduling demo purposes only! In real world the connection
        // may disappear and the continuation will point to stale data!
        TSCont cbcontp = TSContCreate(cert_callback, TSMutexCreate());
        TSContDataSet(cbcontp, vc);
        TSContSchedule(cbcontp, 3000, TS_THREAD_POOL_DEFAULT);
    }
}


static int
plugin_callback(TSCont contp, TSEvent event, void *edata)
{
    TSHttpTxn txnp = (TSHttpTxn) edata;

    switch (event) {
        case TS_EVENT_HTTP_SEND_REQUEST_HDR:
            TSDebug("async_verify", "TS_EVENT_HTTP_SEND_REQUEST_HDR event received, txnp=%p", txnp);
            TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
            break;
        default:
            TSError("[async_verify] unexpected event %d", event);
            break;
    }

    return 0;
}

void
TSPluginInit(int argc, const char *argv[])
{
    TSPluginRegistrationInfo info;
    TSCont txn_contp;
    TSCont vc_contp;

    info.plugin_name = "async-verify-sample-plugin";
    info.vendor_name = "<Vendor>";
    info.support_email = "support@domain.com";

    if (TSPluginRegister(&info) != TS_SUCCESS) {
        TSError("[async_verify] Plugin registration failed.");
        return;
    }

    txn_contp = TSContCreate(plugin_callback, TSMutexCreate());
    vc_contp = TSContCreate(verify_callback, TSMutexCreate());
    TSHttpHookAdd(TS_HTTP_SEND_REQUEST_HDR_HOOK, txn_contp);
    TSHttpHookAdd(TS_SSL_CERT_VERIFY_HOOK, vc_contp);
    return;
}


