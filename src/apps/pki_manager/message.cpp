#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include <snet/crypto/bio.hpp>
#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/cert.hpp>

#include <casket/utils/exception.hpp>
#include "message.hpp"

using namespace casket;

namespace snet
{

const char* CertSignAlgorithmStr[] = {"signTrusted", "signUntrusted", "signSelf", nullptr};

const char* certSignAlgorithm(int sg)
{
    if (sg >= 0 && sg < algSignEnd)
        return CertSignAlgorithmStr[sg];

    return nullptr;
}

CertSignAlgorithm certSignAlgorithmId(const char* sg)
{
    for (int i = 0; i < algSignEnd && CertSignAlgorithmStr[i] != nullptr; i++)
        if (strcmp(CertSignAlgorithmStr[i], sg) == 0)
            return (CertSignAlgorithm)i;

    return algSignEnd;
}

CrtdMessage::CrtdMessage(MessageKind kind)
    : body_size(0)
    , state(kind == REPLY ? BEFORE_LENGTH : BEFORE_CODE)
{
}

CrtdMessage::ParseResult CrtdMessage::parse(const char* buffer, size_t len)
{
    char const* current_pos = buffer;
    while (current_pos != buffer + len && state != END)
    {
        switch (state)
        {
        case BEFORE_CODE:
        {
            if (isspace(*current_pos))
            {
                ++current_pos;
                break;
            }
            if (isalpha(*current_pos))
            {
                state = CODE;
                break;
            }
            clear();
            return ERROR;
        }
        case CODE:
        {
            if (isalnum(*current_pos) || *current_pos == '_')
            {
                current_block += *current_pos;
                ++current_pos;
                break;
            }
            if (isspace(*current_pos))
            {
                code = current_block;
                current_block.clear();
                state = BEFORE_LENGTH;
                break;
            }
            clear();
            return ERROR;
        }
        case BEFORE_LENGTH:
        {
            if (isspace(*current_pos))
            {
                ++current_pos;
                break;
            }
            if (isdigit(*current_pos))
            {
                state = LENGTH;
                break;
            }
            clear();
            return ERROR;
        }
        case LENGTH:
        {
            if (isdigit(*current_pos))
            {
                current_block += *current_pos;
                ++current_pos;
                break;
            }
            if (isspace(*current_pos))
            {
                body_size = atoi(current_block.c_str());
                current_block.clear();
                state = BEFORE_BODY;
                break;
            }
            clear();
            return ERROR;
        }
        case BEFORE_BODY:
        {
            if (body_size == 0)
            {
                state = END;
                break;
            }
            if (isspace(*current_pos))
            {
                ++current_pos;
                break;
            }
            else
            {
                state = BODY;
                break;
            }
        }
        case BODY:
        {
            size_t body_len = (static_cast<size_t>(buffer + len - current_pos) >= body_size - current_block.length())
                                  ? body_size - current_block.length()
                                  : static_cast<size_t>(buffer + len - current_pos);
            current_block += std::string(current_pos, body_len);
            current_pos += body_len;
            if (current_block.length() == body_size)
            {
                body = current_block;
                state = END;
            }
            if (current_block.length() > body_size)
            {
                clear();
                return ERROR;
            }
            break;
        }
        case END:
        {
            return OK;
        }
        }
    }
    if (state != END)
        return INCOMPLETE;
    return OK;
}

std::string const& CrtdMessage::getBody() const
{
    return body;
}

std::string const& CrtdMessage::getCode() const
{
    return code;
}

void CrtdMessage::setBody(std::string const& aBody)
{
    body = aBody;
}

void CrtdMessage::setCode(std::string const& aCode)
{
    code = aCode;
}

std::string CrtdMessage::compose() const
{
    if (code.empty())
        return std::string();
    return code + ' ' + std::to_string(body.length()) + ' ' + body;
}

void CrtdMessage::clear()
{
    body_size = 0;
    state = BEFORE_CODE;
    body.clear();
    code.clear();
    current_block.clear();
}

void CrtdMessage::parseBody(CrtdMessage::BodyParams& map, std::string& other_part) const
{
    other_part.clear();
    // Copy string for using it as temp buffer.
    std::string temp_body(body.c_str(), body.length());
    char* buffer = const_cast<char*>(temp_body.c_str());
    char* token = strtok(buffer, "\r\n");
    while (token != nullptr)
    {
        std::string current_string(token);
        size_t equal_pos = current_string.find('=');
        if (equal_pos == std::string::npos)
        {
            size_t offset_body_part = token - temp_body.c_str();
            other_part = std::string(body.c_str() + offset_body_part, body.length() - offset_body_part);
            break;
        }
        else
        {
            std::string param(current_string.c_str(), current_string.c_str() + equal_pos);
            std::string value(current_string.c_str() + equal_pos + 1);
            map.insert(std::make_pair(param, value));
        }
        token = strtok(nullptr, "\r\n");
    }
}

void CrtdMessage::composeBody(CrtdMessage::BodyParams const& map, std::string const& other_part)
{
    body.clear();
    for (BodyParams::const_iterator i = map.begin(); i != map.end(); ++i)
    {
        if (i != map.begin())
            body += "\n";
        body += i->first + "=" + i->second;
    }
    if (!other_part.empty())
        body += '\n' + other_part;
}

void CrtdMessage::parseRequest(CertificateProperties& certProperties)
{
    CrtdMessage::BodyParams map;
    std::string certs_part;
    parseBody(map, certs_part);
    CrtdMessage::BodyParams::iterator i = map.find(CrtdMessage::param_host);
    if (i == map.end())
    {
        throw RuntimeError("Cannot find \"host\" parameter in request message");
    }
    certProperties.commonName = i->second;

    i = map.find(CrtdMessage::param_SetValidAfter);
    if (i != map.end() && strcasecmp(i->second.c_str(), "on") == 0)
        certProperties.setValidAfter = true;

    i = map.find(CrtdMessage::param_SetValidBefore);
    if (i != map.end() && strcasecmp(i->second.c_str(), "on") == 0)
        certProperties.setValidBefore = true;

    i = map.find(CrtdMessage::param_SetCommonName);
    if (i != map.end())
    {
        // use this as Common Name  instead of the hostname
        // defined with host or Common Name from mimic cert
        certProperties.commonName = i->second;
        certProperties.setCommonName = true;
    }

    i = map.find(CrtdMessage::param_Sign);
    if (i != map.end())
    {
        if ((certProperties.signAlgorithm = certSignAlgorithmId(i->second.c_str())) == algSignEnd)
        {
            throw RuntimeError("Wrong signing algorithm: {}", i->second);
        }
    }
    else
        certProperties.signAlgorithm = algSignTrusted;

    i = map.find(CrtdMessage::param_SignHash);
    const char* signHashName = i != map.end() ? i->second.c_str() : "sha256";
    if (!(certProperties.signHash = EVP_get_digestbyname(signHashName)))
    {
        throw RuntimeError("Wrong signing hash: {}", signHashName);
    }

    auto bio = crypto::BioTraits::createMemoryReader((const uint8_t*)certs_part.data(), certs_part.size());

    certProperties.signWithX509 = crypto::Cert::fromBio(bio);
    certProperties.signWithPkey = crypto::AsymmKey::fromBio(KeyType::Private, bio, Encoding::PEM);

    static const std::string CERT_BEGIN_STR("-----BEGIN CERTIFICATE");
    size_t pos;
    if ((pos = certs_part.find(CERT_BEGIN_STR)) != std::string::npos)
    {
        pos += CERT_BEGIN_STR.length();
        if ((pos = certs_part.find(CERT_BEGIN_STR, pos)) != std::string::npos)
        {
            auto bio =
                crypto::BioTraits::createMemoryReader((const uint8_t*)certs_part.data() + pos, certs_part.size() - pos);
            certProperties.mimicCert = crypto::Cert::fromBio(bio);
        }
    }
}

void CrtdMessage::composeRequest(CertificateProperties const& certProperties)
{
    body.clear();
    body = CrtdMessage::param_host + "=" + certProperties.commonName;
    if (certProperties.setCommonName)
        body += "\n" + CrtdMessage::param_SetCommonName + "=" + certProperties.commonName;
    if (certProperties.setValidAfter)
        body += "\n" + CrtdMessage::param_SetValidAfter + "=on";
    if (certProperties.setValidBefore)
        body += "\n" + CrtdMessage::param_SetValidBefore + "=on";
    if (certProperties.signAlgorithm != algSignEnd)
        body += "\n" + CrtdMessage::param_Sign + "=" + certSignAlgorithm(certProperties.signAlgorithm);
    if (certProperties.signHash)
        body += "\n" + CrtdMessage::param_SignHash + "=" + EVP_MD_name(certProperties.signHash);

    std::string certsPart;

    auto bio = crypto::BioTraits::createMemoryBuffer();

    crypto::Cert::toBio(certProperties.signWithX509, bio, Encoding::PEM);
    crypto::AsymmKey::toBio(KeyType::Private, certProperties.signWithPkey, bio, Encoding::PEM);

    if (certProperties.mimicCert.get())
    {
        crypto::Cert::toBio(certProperties.mimicCert, bio, Encoding::PEM);
    }

    body += "\n" + crypto::BioTraits::getMemoryDataAsString(bio);
}

const std::string CrtdMessage::code_new_certificate("new_certificate");
const std::string CrtdMessage::param_host("host");
const std::string CrtdMessage::param_SetValidAfter("setValidAfter");
const std::string CrtdMessage::param_SetValidBefore("setValidBefore");
const std::string CrtdMessage::param_SetCommonName("setCommonName");
const std::string CrtdMessage::param_Sign("Sign");
const std::string CrtdMessage::param_SignHash("SignHash");

} // namespace snet