#include <stdio.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"

static int make_connection(const char *host, const char *service)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((s = getaddrinfo(host, service, &hints, &result)) != 0) {
        fprintf(stderr, "%s: %s", host, gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1)
            continue;

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
            break;

        close(sock);
    }

    freeaddrinfo(result);

    if (rp == NULL) {
        fprintf(stderr, "%s: failed to connect.", host);
        return -1;
    }

    return sock;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *store)
{
    X509 *cert;
    char buf[256];

    cert = X509_STORE_CTX_get_current_cert(store);
    printf("verify_callback called: preverify_ok=%d\n", preverify_ok);
    printf("| %s\n", X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf)));
    return 1;
}

int main(int argc, char *argv[])
{
    const char hostname[] = "localhost";
    const char port[] = "443";

    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    int sock;
    int ret;

    /* Initialize */
    SSL_load_error_strings();
    if (SSL_library_init() < 0) {
        fprintf(stderr, "Failed to initialize OpenSSL.\n");
        exit(1);
    }
    OpenSSL_add_all_algorithms();

    method = TLSv1_method();
    ctx = SSL_CTX_new(method);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_ASYNC, NULL);

    printf("Connecting to %s:%s...\n", hostname, port);
    sock = make_connection(hostname, port);
    if (sock == -1)
        exit(1);
    fcntl(sock, F_SETFL, O_NONBLOCK);

    bio = BIO_new_socket(sock, BIO_NOCLOSE);
    assert(bio != NULL);
    BIO_set_nbio(bio, 1);

    printf("Connected, initiating TLS handshake...\n");
    ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);
    do {
        ret = SSL_connect(ssl);

        if (ret == 1) {
            printf("Handshake completed.\n");
            break;
        } else if (ret == 0) {
            printf("Handshake did NOT complete.\n");
            break;
        } else {
            int err = SSL_get_error(ssl, ret);
            char buf[256];
            switch (err) {
                case SSL_ERROR_SSL:
                    printf("-> SSL Error: %s\n", ERR_error_string(ERR_get_error(), buf));
                    exit(1);
                case SSL_ERROR_WANT_READ:
                    printf("-> SSL_WANT_READ\n");
                    break;
                case SSL_ERROR_WANT_WRITE:
                    printf("-> SSL_WANT_WRITE\n");
                    break;
                case SSL_ERROR_WANT_CONNECT:
                    printf("-> SSL_WANT_CONNECT\n");
                    break;
                case SSL_ERROR_WANT_X509_VERIFY:
                    printf("-> SSL_WANT_X509_VERIFY\n");
                    //SSL_set_verify_result(ssl, X509_V_ERR_UNABLE_TO_GET_CRL);
                    SSL_set_verify_result(ssl, X509_V_OK);
                    break;
                default:
                    printf("-> %d\n", err);
                    break;
            }
            // Skip async event loop - just wait a bit
            usleep(10000);
        }
    } while(1);
}
