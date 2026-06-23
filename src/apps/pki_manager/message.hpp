#pragma once
#include <map>
#include <string>
#include <snet/crypto/pointers.hpp>

namespace snet
{

enum CertSignAlgorithm
{
    algSignTrusted = 0,
    algSignUntrusted,
    algSignSelf,
    algSignEnd
};

const char* certSignAlgorithm(int sg);

CertSignAlgorithm certSignAlgorithmId(const char* sg);

class CertificateProperties
{
public:
    CertificateProperties()
        : setValidAfter(false)
        , setValidBefore(false)
        , setCommonName(false)
        , signAlgorithm(algSignEnd)
        , signHash(nullptr)
    {
    }

    crypto::X509CertPtr mimicCert;    ///< Certificate to mimic
    crypto::X509CertPtr signWithX509; ///< Certificate to sign the generated request
    crypto::KeyPtr signWithPkey;      ///< The key of the signing certificate
    bool setValidAfter;               ///< Do not mimic "Not Valid After" field
    bool setValidBefore;              ///< Do not mimic "Not Valid Before" field
    bool setCommonName;               ///< Replace the CN field of the mimicking subject with the given
    std::string commonName;           ///< A CN to use for the generated certificate
    CertSignAlgorithm signAlgorithm;  ///< The signing algorithm to use
    const EVP_MD* signHash;           ///< The signing hash to use
private:
    CertificateProperties(CertificateProperties&) = delete;
    CertificateProperties& operator=(CertificateProperties const&) = delete;
};

/**
 * This class is responsible for composing and parsing messages destined to, or coming
 * from an ssl_crtd server. Format of these messages is:
 *   response/request-code SP body length SP body
 */
class CrtdMessage
{
public:
    typedef std::map<std::string, std::string> BodyParams;
    /// Parse result codes.
    enum ParseResult
    {
        OK,
        INCOMPLETE,
        ERROR
    };
    enum MessageKind
    {
        REPLY,
        REQUEST
    };
    CrtdMessage(MessageKind kind);
    /**Parse buffer of length len
     \retval OK          if parsing completes
     \retval INCOMPLETE  if more data required
     \retval ERROR       if there is an error.
     */
    ParseResult parse(const char* buffer, size_t len);
    /// Current  body. If parsing is not finished the method returns incompleted body.
    std::string const& getBody() const;
    /// Current response/request code. If parsing is not finished the method may return incompleted code.
    std::string const& getCode() const;
    void setBody(std::string const& aBody); ///< Set new body to encode.
    void setCode(std::string const& aCode); ///< Set new request/reply code to compose.
    std::string compose() const;            ///< Compose current (request) code and body to string.
    /// Reset the class.
    void clear();
    /**
     *Parse body data which has the form: \verbatim
         param1=value1
         param2=value2
         The other multistring part of body.  \endverbatim
     * The parameters of the body stored to map and the remaining part to other_part
     */
    void parseBody(BodyParams& map, std::string& other_part) const;
    /**
     *Compose parameters given by map with their values and the other part given by
     * other_part to body data. The constructed body will have the form:  \verbatim
         param1=value1
         param2=value2
         The other multistring part of body.  \endverbatim
    */
    void composeBody(BodyParams const& map, std::string const& other_part);

    /// orchestrates entire request parsing
    void parseRequest(CertificateProperties&);
    void composeRequest(CertificateProperties const&); // throws

    /// String code for "new_certificate" messages
    static const std::string code_new_certificate;
    /// Parameter name for passing hostname
    static const std::string param_host;
    /// Parameter name for passing SetValidAfter cert adaptation variable
    static const std::string param_SetValidAfter;
    /// Parameter name for passing SetValidBefore cert adaptation variable
    static const std::string param_SetValidBefore;
    /// Parameter name for passing SetCommonName cert adaptation variable
    static const std::string param_SetCommonName;
    /// Parameter name for passing signing algorithm
    static const std::string param_Sign;
    /// The signing hash to use
    static const std::string param_SignHash;

protected:
    enum ParseState
    {
        BEFORE_CODE,
        CODE,
        BEFORE_LENGTH,
        LENGTH,
        BEFORE_BODY,
        BODY,
        END
    };
    size_t body_size;          ///< The body size if exist or 0.
    ParseState state;          ///< Parsing state.
    std::string body;          ///< Current body.
    std::string code;          ///< Current response/request code.
    std::string current_block; ///< Current block buffer.
};

} // namespace snet
