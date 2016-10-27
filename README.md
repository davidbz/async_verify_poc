Asynchronous Certificate Validation
===================================

This is a proof of concept that extends OpenSSL and Traffic Server to allow
asynchronous verification of certificates when Traffic Server is establishing
connections to SSL servers.

Normally OpenSSL provides a simple verify callback which must return immediately
with a result.  This is not useful if the verification process can be blocking.

Overview
--------

### OpenSSL

Asynchronous mode is enabled by defining a `NULL` verify callback with the
`SSL_VERIFY_ASYNC` new mode.  When a peer certificate chain is received:

1. `SSL_connect()` returns `SSL_ERROR_WANT_X509_VERIFY` to indicate verification
   is required.
2. The application can examine the received chain using
   `SSL_get_peer_cert_chain()`, and update the result using `SSL_set_verify_result()`.
3. In order to resume handshake, `SSL_connect()` is called again.  If the
   result is an error, the SSL state machine will process it as expected and report
   the relevant error to the server.

### Traffic Server

Traffic Server is extended to support the asynchronous verify mode by specifying
the following `records.config` settings:

```
CONFIG proxy.config.ssl.client.verify.server INT 2
```

In this mode, traffic server will invoke a new `TS_SSL_CERT_VERIFY_HOOK` plugin
hook.  The plugin can then examine the passed TSVConn SSL connection and
perform certificate chain verification.  SSL handshake will hang at this stage
and only resume when the plugin calls `TSVConnReenable()` (at the original
callback hook or at any later stage).


Building
--------

### Staging environment

To build and install traffic server and OpenSSL into a local staging directory,
run:

    ./build.sh


Traffic Server depends on libcurl which is compiled against the system's
shared version of OpenSSL.  At least on Ubuntu this causes a conflict because
libcurl.so expects OpenSSL shared objects with versioned symbols, whereas the
default OpenSSL is unversioned.  In order to overcome this, a local version
of curl is built against the local OpenSSL.

### Sample plugin

To build and install the sample plugin, run:

    cd sample_plugin
    make
    make install


Configuring and Running
-----------------------

Configure the plugin by adding to `staging/etc/trafficserver/plugin.config`
the following line:

    async_verify.so

Configure traffic server by adding to `staging/etc/trafficserver/records.config`
the following lines:

    CONFIG proxy.config.diags.debug.enabled INT 1
    CONFIG proxy.config.diags.debug.tags STRING async_verify.*|ssl.*
    CONFIG proxy.config.url_remap.remap_required INT 0
    CONFIG proxy.config.ssl.client.verify.server INT 2

Run traffic server directly with logging to stdout:

    ./staging/bin/traffic_server


Testing the plugin
------------------

Initiate an outgoing HTTPS connection by establishing a connection with
traffic server (e.g. `telnet localhost 8080`) and sending the following
request:

    GET https://www.google.com HTTP/1.1
    Host: www.google.com

This will result with an error, because the sample plugin blocks Google
certificates.

Accessing `https://www.facebook.com` the same way should work, and acessing
`https://www.twitter.com` the same way should work but introduce a delay as the
hook does NOT immediately approve the certificate but instead schedules
a traffic server continuation to fire 3000ms later and only then it
re-enables the SSL handshake.

