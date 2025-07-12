#include <iostream>
#include <iomanip>

#include <casket/opt/option_builder.hpp>
#include <casket/opt/cmd_line_options_parser.hpp>
#include <casket/utils/exception.hpp>

#include <snet/cli/command_dispatcher.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

static constexpr int columnIDWidth = 12;
static constexpr int columnEncryptionWidth = 20;
static constexpr int columnAlgorithmWidth = 15;
static constexpr int columnKeyBitsWidth = 10;
static constexpr int columnNameWidth = 40;

using namespace casket;
using namespace casket::opt;
using namespace snet::tls;

namespace snet
{

class CipherListCommand final : public cmd::Command
{
public:
    CipherListCommand();

    ~CipherListCommand() = default;

    void execute(const std::vector<std::string_view>& args) override;

    void print(const std::vector<const tls::CipherSuite*>& cipherSuites);

    void print(const tls::CipherSuite* cipherSuite);

    std::string convert(const std::uint16_t number);

private:
    CmdLineOptionsParser parser_;
    std::string suite_;
    std::string version_;
    int securityLevel_;
};

REGISTER_COMMAND("cipherlist", "List supported TLS cipher suites", CipherListCommand);

CipherListCommand::CipherListCommand()
    : securityLevel_(-1)
{
    // clang-format off
    parser_.add(
        OptionBuilder("help")
            .setDescription("Print help message")
            .build()
    );
    parser_.add(
        OptionBuilder("level", Value(&securityLevel_))
            .setDescription("Security level [0..5]")
            .build()
    );
    parser_.add(
        OptionBuilder("suite", Value(&suite_))
            .setDescription("Show selected cipher suite, format 'XX,XX', where X - hex digit")
            .build()
    );
    parser_.add(
        OptionBuilder("version", Value(&version_))
            .setDescription("Show only version-specific cipher suites: sslv3.0, tlsv1.0, tlsv1.1, tlsv1.2, tlsv1.3")
            .build()
    );
    // clang-format on
}

void CipherListCommand::execute(const std::vector<std::string_view>& args)
{
    parser_.parse(args);
    if (parser_.isUsed("help"))
    {
        parser_.help(std::cout, "snet cipherlist");
        return;
    }
    parser_.validate();

    if (securityLevel_ > 0)
    {
        tls::CipherSuiteManager::getInstance().setSecurityLevel(securityLevel_);
    }

    if (!version_.empty())
    {
        auto version = ProtocolVersion::fromString(version_);
        tls::CipherSuiteManager::getInstance().setVersion(version.value_or(ProtocolVersion()));
    }

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

    std::cout << std::string(2 * columnIDWidth + columnEncryptionWidth + 3 * columnAlgorithmWidth + columnKeyBitsWidth +
                                 columnNameWidth,
                             '-')
              << std::endl;

    if (!suite_.empty())
    {
        auto commaPosition = suite_.find(',');
        casket::ThrowIfTrue(commaPosition == std::string::npos, "Invalid format for cipher suite");

        std::string firstPart = suite_.substr(0, commaPosition);
        std::string secondPart = suite_.substr(commaPosition + 1);

        std::uint16_t firstValue = static_cast<std::uint16_t>(std::stoi(firstPart, nullptr, 16));
        std::uint16_t secondValue = static_cast<std::uint16_t>(std::stoi(secondPart, nullptr, 16));

        // Объединяем два значения в одно 16-битное число
        std::uint16_t result = (firstValue << 8) | secondValue;
        auto cipherSuite = tls::CipherSuiteManager::getInstance().getCipherSuiteById(result);
        casket::ThrowIfFalse(cipherSuite, "Cipher suite '" + suite_ + "' not found");
        print(cipherSuite);
    }
    else
    {
        auto cipherSuites = tls::CipherSuiteManager::getInstance().getCipherSuites();
        print(cipherSuites);
    }
}

void CipherListCommand::print(const std::vector<const tls::CipherSuite*>& cipherSuites)
{
    for (const auto& cipherSuite : cipherSuites)
    {
        print(cipherSuite);
    }
}

void CipherListCommand::print(const tls::CipherSuite* cipherSuite)
{
    // clang-format off
    std::cout << std::left
              << std::setw(columnIDWidth) << convert(CipherSuiteGetID(cipherSuite))
              << std::setw(columnIDWidth) << CipherSuiteGetVersion( cipherSuite )
              << std::setw(columnEncryptionWidth) << CipherSuiteGetCipherName(cipherSuite)
              << std::setw(columnAlgorithmWidth)
              << (CipherSuiteIsAEAD(cipherSuite) ? "AEAD" : CipherSuiteGetHmacDigestName(cipherSuite))
              << std::setw(columnAlgorithmWidth) << OBJ_nid2sn(CipherSuiteGetKeyExchange(cipherSuite))
              << std::setw(columnAlgorithmWidth) << OBJ_nid2sn(CipherSuiteGetAuth(cipherSuite))
              << std::setw(columnKeyBitsWidth) << CipherSuiteGetKeySize(cipherSuite)
              << std::setw(columnNameWidth) << CipherSuiteGetName(cipherSuite)
              << std::endl;
    // clang-format on
}

std::string CipherListCommand::convert(const std::uint16_t value)
{
    std::ostringstream oss;

    std::uint8_t highByte = (value >> 8) & 0xFF;
    std::uint8_t lowByte = value & 0xFF;

    oss << "0x" << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << static_cast<int>(highByte)
        << ",0x" << std::setw(2) << std::setfill('0') << static_cast<int>(lowByte);

    return oss.str();
}

} // namespace snet
