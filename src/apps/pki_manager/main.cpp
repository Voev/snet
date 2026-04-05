#include <iostream>
#include <thread>
#include <chrono>

#include <casket/transport/unix_socket.hpp>
#include <casket/server/generic_server.hpp>

#include <casket/utils/string.hpp>

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

#include <snet/cert_cache/cert_manager.hpp>
#include <snet/cert_cache/cert_cache.hpp>
#include "message.hpp"

#include <casket/opt/cmd_line_options_parser.hpp>
#include <casket/opt/option_builder.hpp>
#include <casket/opt/option_value_handler.hpp>

using namespace casket;
using namespace casket::opt;
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

/*static const char* const B_KBYTES_STR = "KB";
static const char* const B_MBYTES_STR = "MB";
static const char* const B_GBYTES_STR = "GB";
static const char* const B_BYTES_STR = "B";

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
}*/

/*
static size_t parseBytesOptionValue(const char* const name, const char* const value)
{
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
*/

class CommandProcessor
{
private:
    GenericServer<UnixSocket> server_;
    std::unique_ptr<CertificateManager> renewer_;
    std::string storageDir_;

    std::string handleInit()
    {
        if (renewer_->databaseExists())
        {
            return "ERROR: Database already initialized";
        }

        if (renewer_->initDatabase())
        {
            return "OK: Database initialized successfully";
        }
        else
        {
            return "ERROR: Failed to initialize database";
        }
    }

    std::string handleListProfiles()
    {
        std::vector<Profile> profiles = renewer_->getAvailableProfiles();

        if (profiles.empty())
        {
            return "No profiles available";
        }

        std::ostringstream response;
        response << "Available profiles:\n";
        for (const auto& profile : profiles)
        {
            response << "  - " << profile.name << " (validity: " << profile.validityDays << " days)\n";
        }

        return response.str();
    }

    std::string handleRenew(const std::string& certPath, const std::string& profileName)
    {
        std::ifstream ifs(certPath);
        if (!ifs.good())
        {
            return "ERROR: Certificate file not found: " + certPath;
        }

        std::string outputPath;
        if (renewer_->renewCertificate(certPath, profileName, outputPath))
        {
            return "OK: Certificate renewed successfully\nOutput: " + outputPath;
        }
        else
        {
            return "ERROR: Failed to renew certificate";
        }
    }

    std::string handleHelp()
    {
        return "Commands:\n"
               "  init                    - Initialize database\n"
               "  list-profiles           - List available renewal profiles\n"
               "  renew <cert> <profile>  - Renew certificate with specified profile\n"
               "  add-profile <name> <ca_cert> <ca_key> <days> - Add new profile\n"
               "  help                    - Show this help";
    }

    std::string handleAddProfile(const std::string& name, const std::string& caCertPath, const std::string& caKeyPath,
                                 int validityDays)
    {
        std::ifstream ifs1(caCertPath);
        if (!ifs1)
        {
            return "ERROR: CA certificate not found: " + caCertPath;
        }

        std::ifstream ifs2(caKeyPath);
        if (!ifs2.good())
        {
            return "ERROR: CA key not found: " + caKeyPath;
        }

        Profile newProfile;
        newProfile.name = name;
        newProfile.caCertPath = caCertPath;
        newProfile.caKeyPath = caKeyPath;
        newProfile.validityDays = validityDays;

        renewer_->addProfile(newProfile);
        return "OK: Profile '" + name + "' added successfully";
    }

    std::string handleStatus()
    {
        std::ostringstream response;
        response << "Server status:\n";
        response << "  Storage directory: " << storageDir_ << "\n";
        response << "  Database initialized: " << (renewer_->databaseExists() ? "yes" : "no") << "\n";
        response << "  Available profiles: " << renewer_->getAvailableProfiles().size() << "\n";
        return response.str();
    }

    std::string processCommand(const std::string& request)
    {
        std::vector<std::string> tokens = casket::split(request, " ");
        if (tokens.empty())
        {
            return "ERROR: Empty command";
        }

        const std::string& command = tokens[0];

        std::cout << "'" << command << "'" << std::endl;

        if (command == "init")
        {
            return handleInit();
        }
        else if (command == "list-profiles" || command == "profiles")
        {
            return handleListProfiles();
        }
        else if (command == "renew")
        {
            if (tokens.size() < 3)
            {
                return "ERROR: Usage: renew <certificate_path> <profile_name>";
            }
            return handleRenew(tokens[1], tokens[2]);
        }
        else if (command == "add-profile")
        {
            if (tokens.size() < 5)
            {
                return "ERROR: Usage: add-profile <name> <ca_cert_path> <ca_key_path> <validity_days>";
            }

            int validityDays;
            try
            {
                validityDays = std::stoi(tokens[4]);
            }
            catch (const std::exception&)
            {
                return "ERROR: Invalid validity days value";
            }

            return handleAddProfile(tokens[1], tokens[2], tokens[3], validityDays);
        }
        else if (command == "status")
        {
            return handleStatus();
        }
        else if (command == "help" || command == "?")
        {
            return handleHelp();
        }
        else
        {
            return "ERROR: Unknown command: " + command + "\nType 'help' for available commands";
        }
    }

public:
    explicit CommandProcessor(const std::string& storageDir)
        : storageDir_(storageDir)
    {
        renewer_ = std::make_unique<CertificateManager>(storageDir_);

        server_.setConnectionHandler(
            [this](UnixSocket& client, const std::vector<uint8_t>& data)
            {
                std::string request(data.begin(), data.end());
                trim(request);
                std::cout << "Received request: '" << request << "'" << std::endl;

                // Process the command
                std::string response = processCommand(request);

                // Add newline for better formatting
                response += "\n";

                std::cout << "Sending response: " << response;
                client.send(reinterpret_cast<const uint8_t*>(response.c_str()), response.size());
            });

        server_.setErrorHandler([](const std::error_code& ec)
                                { std::cerr << "Server error: " << ec.message() << std::endl; });
    }

    bool start(const std::string& address)
    {
        if (!server_.listen(address))
        {
            std::cerr << "Failed to listen on " << address << std::endl;
            return false;
        }

        std::cout << "Certificate renewal server started on " << address << std::endl;
        std::cout << "Storage directory: " << storageDir_ << std::endl;
        server_.start();
        return true;
    }

    void stop()
    {
        server_.stop();
        std::cout << "Server stopped" << std::endl;
    }

    bool isRunning() const
    {
        return server_.isRunning();
    }

    // Additional utility methods
    void setStorageDirectory(const std::string& dir)
    {
        storageDir_ = dir;
        renewer_ = std::make_unique<CertificateManager>(storageDir_);
    }

    bool addDefaultProfile()
    {
        if (renewer_->getAvailableProfiles().empty())
        {
            Profile defaultProfile;
            defaultProfile.name = "default";
            defaultProfile.caCertPath = storageDir_ + "/ca.crt";
            defaultProfile.caKeyPath = storageDir_ + "/ca.key";
            defaultProfile.validityDays = 365;

            renewer_->addProfile(defaultProfile);
            return true;
        }
        return false;
    }
};

class Executor
{
public:
    struct Arguments
    {
        std::string dbPath;
        size_t fsBlockSize{0};
        size_t maxDbSize{0};
    };

    Executor()
    {
        // clang-format off
        parser_.add(
            OptionBuilder("help")
                .setDescription("Print help message")
                .build()
        );        
        parser_.add(
            OptionBuilder("create-db")
                .setDescription("Init database directory and exit")
                .build()
        );        
        parser_.add(
            OptionBuilder("db-path", Value(&args_.dbPath))
                .setDescription("Directory path of SSL storage database")
                .build()
        );        
        parser_.add(
            OptionBuilder("max-db-size", Value(&args_.maxDbSize))
                .setDescription("Maximum size of disk storage")
                .build()
        );        
        parser_.add(
            OptionBuilder("fs-block-size", Value(&args_.fsBlockSize))
                .setDescription("File system block size in bytes")
                .setDefaultValue(2048)
                .build()
        );
        // clang-format on
    }

    void parse(std::vector<nonstd::string_view> args)
    {
        parser_.parse(args);
    }

    void run();

private:
    CmdLineOptionsParser parser_;
    Arguments args_;
};

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

/*static bool processNewRequest(CrtdMessage& request_message, std::string const& db_path, size_t max_db_size,
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
}*/

void Executor::run()
{
    if (parser_.isUsed("help"))
    {
        parser_.help(std::cout, "pki_manager");
        return;
    }
    parser_.validate();

    CommandProcessor proc(args_.dbPath);

    if (!proc.start("/tmp/cert_signer"))
    {
        return;
    }

    while (proc.isRunning())
    {
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    /*
    if (!args_.dbPath.empty() && args_.maxDbSize == 0)
        throw RuntimeError("security_file_certgen -s requires an -M parameter");

    if (parser_.isUsed("create"))
    {
        std::cout << "Initialization SSL db..." << std::endl;
        CertificateDb::Create(args_.dbPath);
        std::cout << "Done" << std::endl;
    }
    else
    {
        auto fsBlockSize = args_.fsBlockSize;
        if (fsBlockSize == 0)
        {
            try
            {
                struct statvfs sfs;
                if (statvfs(args_.dbPath.c_str(), &sfs) == 0)
                {
                    fsBlockSize = std::max(sfs.f_frsize, static_cast<decltype(sfs.f_frsize)>(512));
                }
                else
                {
                    fsBlockSize = 2048;
                }
            }
            catch (...)
            {
                fsBlockSize = 2048;
            }
        }

        CertificateDb::Check(args_.dbPath, args_.maxDbSize, args_.fsBlockSize);

        for (;;)
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
                processNewRequest(request_message, args_.dbPath, args_.maxDbSize, args_.fsBlockSize);
            }
            else
            {
                throw RuntimeError("Unknown request code: \"{}\"", request_message.getCode());
            }
            std::cout.flush();
        }
    }*/
}

int main(int argc, char* argv[])
{
    try
    {
        std::vector<std::string_view> args(argv + 1, argv + argc);
        if (args.empty())
        {
            std::cerr << "Use '--help' to print help message." << std::endl;
            return EXIT_FAILURE;
        }

        Executor executor;
        executor.parse(args);
        executor.run();
    }
    catch (std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
