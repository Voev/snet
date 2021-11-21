#pragma once
#include <openssl/ssl.h>
#include <stdexcept>

struct SslContext
{
  public:
    explicit SslContext(const SSL_METHOD* meth)
        : ctx_(SSL_CTX_new(meth))
    {
        if (!ctx_)
            throw std::bad_alloc();
    }

    ~SslContext()
    {
        SSL_CTX_free(ctx_);
        BIO_free(out_);
    }

    SSL_CTX* Get0() const
    {
        return ctx_;
    }

    void LoadPrivateKey(const std::string& filename)
    {
        if (!SSL_CTX_use_PrivateKey_file(ctx_, filename.c_str(),
                                         SSL_FILETYPE_PEM))
        {
            throw std::runtime_error("failed to load private key");
        }
    }

    void LoadCertificate(const std::string& filename)
    {
        if (!SSL_CTX_use_certificate_file(ctx_, filename.c_str(),
                                          SSL_FILETYPE_PEM))
        {
            throw std::runtime_error("failed to load certificate");
        }
    }

    void EnableTlsTrace()
    {
        SSL_CTX_set_msg_callback(ctx_, SSL_trace);
        out_ = BIO_new_fp(stdout, BIO_NOCLOSE);
        SSL_CTX_set_msg_callback_arg(ctx_, out_);
    }

    void SetMaxVersion(int version)
    {
        SSL_CTX_set_max_proto_version(ctx_, version);
    }

  private:
    SSL_CTX* ctx_{nullptr};
    BIO* out_{nullptr};
};
