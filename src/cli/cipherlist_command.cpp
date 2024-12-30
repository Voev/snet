#include <iostream>
#include <iomanip>

#include <casket/opt/option_parser.hpp>

#include <snet/cli/command_dispatcher.hpp>

#include <snet/tls/cipher_suite_manager.hpp>

static constexpr int columnIDWidth = 12;
static constexpr int columnEncryptionWidth = 20;
static constexpr int columnAlgorithmWidth = 15;
static constexpr int columnKeyBitsWidth = 10;
static constexpr int columnNameWidth = 40;

using namespace casket;

namespace snet
{

class CipherListCommand final : public cmd::Command
{
public:
    CipherListCommand();

    ~CipherListCommand() = default;

    void execute(const std::vector<std::string_view>& args) override;

    void print(const std::vector<tls::CipherSuite>& cipherSuites);

    void print(const tls::CipherSuite& cipherSuite);

    std::string convert(const std::uint16_t number);

private:
    opt::OptionParser parser_;
    int securityLevel_;
    bool supported_;
};

REGISTER_COMMAND("cipherlist", "List supported TLS cipher suites", CipherListCommand);

CipherListCommand::CipherListCommand()
    : securityLevel_(-1)
    , supported_(false)
{
    parser_.add("help, h", "Print help message");
    parser_.add("level, l", opt::Value(&securityLevel_), "Security level [0..5]");
    parser_.add("supported, s", opt::Value(&supported_), "Show only supported cipher suites");
}

void CipherListCommand::execute(const std::vector<std::string_view>& args)
{
    parser_.parse(args);
    if (parser_.isUsed("help"))
    {
        parser_.help(std::cout);
        return;
    }

    if (securityLevel_ > 0)
    {
        tls::CipherSuiteManager::getInstance().setSecurityLevel(securityLevel_);
    }

    auto cipherSuites = tls::CipherSuiteManager::getInstance().getCipherSuites(supported_);

    // clang-format off
    std::cout << std::left
              << std::setw(columnIDWidth) << "ID"
              << std::setw(columnIDWidth) << "Version"
              << std::setw(columnEncryptionWidth) << "Encryption"
              << std::setw(columnAlgorithmWidth) << "Hash"
              << std::setw(columnAlgorithmWidth) << "Key exchange"
              << std::setw(columnAlgorithmWidth) << "Authentication"
              << std::setw(columnKeyBitsWidth) << "Key bits"
              << std::setw(columnNameWidth) << "Name"
              << std::endl;
    // clang-format on

    std::cout << std::string(2 * columnIDWidth + columnEncryptionWidth + 3 * columnAlgorithmWidth +
                                 columnKeyBitsWidth + columnNameWidth,
                             '-')
              << std::endl;

    print(cipherSuites);
}

void CipherListCommand::print(const std::vector<tls::CipherSuite>& cipherSuites)
{
    for (const auto& cipherSuite : cipherSuites)
    {
        print(cipherSuite);
    }
}

void CipherListCommand::print(const tls::CipherSuite& cipherSuite)
{
    // clang-format off
    std::cout << std::left
              << std::setw(columnIDWidth) << convert(cipherSuite.getID())
              << std::setw(columnIDWidth) << cipherSuite.getVersion()
              << std::setw(columnEncryptionWidth) << cipherSuite.getCipherName()
              << std::setw(columnAlgorithmWidth)
              << (cipherSuite.isAEAD() ? "AEAD" : cipherSuite.getDigestName())
              << std::setw(columnAlgorithmWidth) << cipherSuite.getKeyExchName().substr(2)
              << std::setw(columnAlgorithmWidth) << cipherSuite.getAuthName().substr(4)
              << std::setw(columnKeyBitsWidth) << cipherSuite.getKeyBits()
              << std::setw(columnNameWidth) << cipherSuite.getSuiteName()
              << std::endl;
    // clang-format on
}

std::string CipherListCommand::convert(const std::uint16_t value)
{
    std::ostringstream oss;

    std::uint8_t highByte = (value >> 8) & 0xFF;
    std::uint8_t lowByte = value & 0xFF;

    oss << "0x" << std::setw(2) << std::setfill('0') << std::hex << std::uppercase
        << static_cast<int>(highByte) << ",0x" << std::setw(2) << std::setfill('0')
        << static_cast<int>(lowByte);

    return oss.str();
}

} // namespace snet
