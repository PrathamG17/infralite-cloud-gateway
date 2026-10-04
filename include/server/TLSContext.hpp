#pragma once
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

/** Owns an OpenSSL server context loaded from a certificate and private key. */
class TLSContext
{
private:
    std::string certFile;
    std::string keyFile;
    SSL_CTX* ctx;

public:
    /** Stores the certificate and private-key file paths.
     * @param cert PEM server certificate path.
     * @param key PEM private-key path.
     * @return No value.
     */
    TLSContext(const std::string& cert, const std::string& key);

    /** Releases the OpenSSL context when initialized. */
    ~TLSContext();

    /** Loads certificate/key material and validates the key pair.
     * @return True when the TLS context is ready for server handshakes.
     */
    bool Init();

    /** Returns the underlying OpenSSL context for handshake setup.
     * @return Owned SSL_CTX pointer, or nullptr before successful initialization.
     */
    SSL_CTX* GetCTX() const;
};
