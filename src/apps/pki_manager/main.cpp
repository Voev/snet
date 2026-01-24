#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <filesystem>
#include <getopt.h>
#include <fstream>

#include <sys/statvfs.h>

#include <casket/utils/exception.hpp>
#include <snet/crypto/bio.hpp>
#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_forger.hpp>
#include <snet/crypto/rsa_asymm_key.hpp>

#include <snet/cert_cache/cert_cache.hpp>
#include "message.hpp"

using namespace casket;
using namespace snet;
using namespace snet::crypto;

const ASN1_BIT_STRING* X509_get_signature(const crypto::X509CertPtr& cert)
{
    const ASN1_BIT_STRING* sig = nullptr;
    const X509_ALGOR* sig_alg = nullptr;

    X509_get0_signature(&sig, &sig_alg, cert.get());
    return sig;
}

static void printX509Signature(const crypto::X509CertPtr& cert, std::string& out)
{
    const ASN1_BIT_STRING* sig = X509_get_signature(cert);
    if (sig && sig->data)
    {
        const unsigned char* s = sig->data;
        for (int i = 0; i < sig->length; ++i)
        {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", s[i]);
            out.append(hex);
        }
    }
}

std::string& OnDiskCertificateDbKey(const CertificateProperties& properties)
{
    static std::string certKey;
    certKey.clear();
    certKey.reserve(4096);
    if (properties.mimicCert.get())
        printX509Signature(properties.mimicCert, certKey);

    if (certKey.empty())
    {
        certKey.append("/CN=", 4);
        certKey.append(properties.commonName);
    }

    if (properties.setValidAfter)
        certKey.append("+SetValidAfter=on", 17);

    if (properties.setValidBefore)
        certKey.append("+SetValidBefore=on", 18);

    if (properties.setCommonName)
    {
        certKey.append("+SetCommonName=", 15);
        certKey.append(properties.commonName);
    }

    if (properties.signAlgorithm != algSignEnd)
    {
        certKey.append("+Sign=", 6);
        certKey.append(certSignAlgorithm(properties.signAlgorithm));
    }

    if (properties.signHash != nullptr)
    {
        certKey.append("+SignHash=", 10);
        certKey.append(EVP_MD_name(properties.signHash));
    }

    return certKey;
}

static const char* const B_KBYTES_STR = "KB";
static const char* const B_MBYTES_STR = "MB";
static const char* const B_GBYTES_STR = "GB";
static const char* const B_BYTES_STR = "B";

/**
 * Parse bytes unit. It would be one of the next value: MB, GB, KB or B.
 * This function is caseinsensitive.
 */
static size_t parseBytesUnits(const char* unit)
{
    if (!strncasecmp(unit, B_BYTES_STR, strlen(B_BYTES_STR)) || !strncasecmp(unit, "", strlen(unit)))
        return 1;

    if (!strncasecmp(unit, B_KBYTES_STR, strlen(B_KBYTES_STR)))
        return 1 << 10;

    if (!strncasecmp(unit, B_MBYTES_STR, strlen(B_MBYTES_STR)))
        return 1 << 20;

    if (!strncasecmp(unit, B_GBYTES_STR, strlen(B_GBYTES_STR)))
        return 1 << 30;

    throw RuntimeError("Unknown bytes unit: {}", unit);
}

/// Parse the number of bytes given as <integer><unit> value (e.g., 4MB).
/// \param name the name of the option being parsed
static size_t parseBytesOptionValue(const char* const name, const char* const value)
{
    // Find number from string beginning.
    char const* number_begin = value;
    char const* number_end = value;

    while ((*number_end >= '0' && *number_end <= '9'))
    {
        ++number_end;
    }

    if (number_end <= number_begin)
        throw RuntimeError("expecting a decimal number at the beginning of {} value but got: ", name, value);

    std::string number(number_begin, number_end - number_begin);
    std::istringstream in(number);
    size_t base = 0;
    if (!(in >> base) || !in.eof())
        throw RuntimeError("unsupported integer part of {} value {}", name, number);

    const auto multiplier = parseBytesUnits(number_end);
    static_assert(std::is_unsigned<decltype(multiplier * base)>::value, "no signed overflows");
    const auto product = multiplier * base;
    if (base && multiplier != product / base)
        throw RuntimeError("{} size too large: {}", name, value);

    return product;
}

/// Print help using response code.
static void usage()
{
    std::string example_host_name = "host.dom";
    std::string request_string = CrtdMessage::param_host + "=" + example_host_name;
    std::stringstream request_string_size_stream;
    request_string_size_stream << request_string.length();
    std::string help_string = "usage: security_file_certgen -hv -s directory -M size -b fs_block_size\n"
                              "\t-h                   Help\n"
                              "\t-v                   Version\n"
                              "\t-s directory         Directory path of SSL storage database.\n"
                              "\t-M size              Maximum size of SSL certificate disk storage.\n"
                              "\t-b fs_block_size     File system block size in bytes. Need for processing\n"
                              "\t                     natural size of certificate on disk. Default value is\n"
                              "\t                     2048 bytes.\n"
                              "\n"
                              "After running write requests in the next format:\n"
                              "<request code><whitespace><body_len><whitespace><body>\n"
                              "There are two kind of request now:\n" +
                              CrtdMessage::code_new_certificate + " " + request_string_size_stream.str() + " " +
                              request_string + "\n" +
                              "\tCreate new private key and selfsigned certificate for \"host.dom\".\n" +
                              CrtdMessage::code_new_certificate + " xxx " + request_string + "\n" +
                              "-----BEGIN CERTIFICATE-----\n"
                              "...\n"
                              "-----END CERTIFICATE-----\n"
                              "-----BEGIN RSA PRIVATE KEY-----\n"
                              "...\n"
                              "-----END RSA PRIVATE KEY-----\n"
                              "\tCreate new private key and certificate request for \"host.dom\"\n"
                              "\tSign new request by received certificate and private key.\n"
                              "usage: security_file_certgen -c -s ssl_store_path\n"
                              "\t-c                   Init ssl db directories and exit.\n";
    std::cerr << help_string << std::endl;
}

/// Process new request message.
static bool processNewRequest(CrtdMessage& request_message, std::string const& db_path, size_t max_db_size,
                              size_t fs_block_size)
{
    CertificateProperties certProperties;
    request_message.parseRequest(certProperties);

    // TODO: create a DB object only once, instead re-allocating here on every call.
    std::unique_ptr<CertificateDb> db;
    if (!db_path.empty())
        db.reset(new CertificateDb(db_path, max_db_size, fs_block_size));

    crypto::X509CertPtr cert;
    crypto::KeyPtr pkey;
    crypto::X509CertPtr orig;
    std::string& certKey = OnDiskCertificateDbKey(certProperties);

    bool dbFailed = false;
    try
    {
        if (db)
            db->find(certKey, certProperties.mimicCert, cert, pkey);
    }
    catch (std::exception& e)
    {
        dbFailed = true;
        std::cerr << "ERROR: Database search failure: " << e.what() << "database location: " << db_path << std::endl;
    }

    if (!cert || !pkey)
    {
        pkey = RsaAsymmKey::generate(2048);
        CertForger forger(certProperties.signWithPkey, certProperties.signWithX509);

        cert = forger.resign(pkey, certProperties.mimicCert);

        try
        {
            if (!dbFailed && db && !db->addCertAndPrivateKey(certKey, cert, pkey, certProperties.mimicCert))
                throw RuntimeError("Cannot add certificate to db.");
        }
        catch (std::exception& e)
        {
            dbFailed = true;
            std::cerr << "ERROR: Database update failure: " << e.what() << "database location: " << db_path
                      << std::endl;
        }
    }

    auto bio = BioTraits::createMemoryBuffer();

    Cert::toBio(cert, bio, Encoding::PEM);
    AsymmKey::toBio(KeyType::Private, pkey, bio, Encoding::PEM);

    auto bufferToWrite = BioTraits::getMemoryDataAsString(bio);

    CrtdMessage response_message(CrtdMessage::REPLY);
    response_message.setCode("OK");
    response_message.setBody(bufferToWrite);

    // Use the '\1' char as end-of-message character
    std::cout << response_message.compose() << '\1' << std::flush;

    return true;
}

std::string readFileToString(const std::string& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open())
    {
        throw std::runtime_error("failed to open: " + filePath);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

/// This is the external security_file_certgen process.
int main(int argc, char* argv[])
{
    try
    {

        size_t max_db_size = 0;
        size_t fs_block_size = 0;
        int8_t c;
        bool create_new_db = false;
        std::string db_path;
        // process options.
        while ((c = getopt(argc, argv, "chvs:M:b:")) != -1)
        {
            switch (c)
            {
            case 'b':
                fs_block_size = parseBytesOptionValue("-b", optarg);
                break;
            case 's':
                db_path = optarg;
                break;
            case 'M':
                // use of -M without -s is probably an admin mistake, so make it an error
                if (db_path.empty())
                {
                    throw RuntimeError("Error -M option requires an -s parameter be set first.");
                }
                max_db_size = parseBytesOptionValue("-M", optarg);
                break;
            case 'v':
                std::cout << "security_file_certgen version 1.0" << std::endl;
                exit(EXIT_SUCCESS);
                break;
            case 'c':
                create_new_db = true;
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            default:
                exit(EXIT_FAILURE);
            }
        }

        // when -s is used, -M is required
        if (!db_path.empty() && max_db_size == 0)
            throw RuntimeError("security_file_certgen -s requires an -M parameter");

        if (create_new_db)
        {
            // when -c is used, -s is required (implying also -M, which is checked above)
            if (db_path.empty())
                throw RuntimeError("security_file_certgen is missing the required parameter. There should be -s and -M "
                                   "parameters when -c is used.");

            std::cout << "Initialization SSL db..." << std::endl;
            CertificateDb::Create(db_path);
            std::cout << "Done" << std::endl;
            exit(EXIT_SUCCESS);
        }

        if (!db_path.empty())
        {
            if (fs_block_size == 0)
            {
                try
                {
                    // Если нужен именно размер блока файловой системы,
                    // придется использовать platform-specific API или оставить statvfs
                    struct statvfs sfs;
                    if (statvfs(db_path.c_str(), &sfs) == 0)
                    {
                        fs_block_size = std::max(sfs.f_frsize, static_cast<decltype(sfs.f_frsize)>(512));
                    }
                    else
                    {
                        fs_block_size = 2048;
                    }
                }
                catch (...)
                {
                    fs_block_size = 2048;
                }
            }
            CertificateDb::Check(db_path, max_db_size, fs_block_size);
        }

        // Initialize SSL subsystem
        // process request.

        // for (;;)
        {
            CrtdMessage request_message(CrtdMessage::REQUEST);
            CrtdMessage::ParseResult parse_result = CrtdMessage::INCOMPLETE;

            std::string request = readFileToString("request.txt");
            parse_result = request_message.parse(request.data(), request.size());

            if (parse_result == CrtdMessage::ERROR)
            {
                throw RuntimeError("Cannot parse request message.");
            }
            else if (request_message.getCode() == CrtdMessage::code_new_certificate)
            {
                processNewRequest(request_message, db_path, max_db_size, fs_block_size);
            }
            else
            {
                throw RuntimeError("Unknown request code: \"{}\"", request_message.getCode());
            }
            std::cout.flush();
        }
    }
    catch (std::exception& e)
    {
        std::cout << "FATAL: Cannot generate certificates: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
