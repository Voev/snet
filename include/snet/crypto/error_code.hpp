/// @file
/// @brief Declaration of error handling functions for cryptography.

#pragma once
#include <system_error>
#include <openssl/x509_vfy.h>

namespace snet::crypto
{

/// @brief Translates an error code from an unsigned long to a std::error_code.
/// @param error The error code to translate.
/// @return The corresponding std::error_code.
std::error_code TranslateError(unsigned long error);

/// @brief Retrieves the last error that occurred.
/// @return The last error as a std::error_code.
std::error_code GetLastError();

} // namespace snet::crypto

namespace snet::crypto::verify
{

enum class Error
{
    No = X509_V_OK,
    Unspecified = X509_V_ERR_UNSPECIFIED,
    UnableToGetIssuerCert = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
    UnableToGetCRL = X509_V_ERR_UNABLE_TO_GET_CRL,
    UnableToDecryptCertSignature = X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,
    UnableToDecryptCRLSignature = X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
    UnableToDecodeIssuerPublicKey = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY,
    CertSignatureFailure = X509_V_ERR_CERT_SIGNATURE_FAILURE,
    CRLSignatureFailure = X509_V_ERR_CRL_SIGNATURE_FAILURE,
    CertNotYetValid = X509_V_ERR_CERT_NOT_YET_VALID,
    CertHasExpired = X509_V_ERR_CERT_HAS_EXPIRED,
    CRLNotYetValid = X509_V_ERR_CRL_NOT_YET_VALID,
    CRLHasExpired = X509_V_ERR_CRL_HAS_EXPIRED,
    InvalidNotBeforeField = X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD,
    InvalidNotAfterField = X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD,
    InvalidLastUpdateField = X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD,
    InvalidNextUpdateField = X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD,
    OutOfMemory = X509_V_ERR_OUT_OF_MEM,
    SelfSignedCert = X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
    SelfSignedCertInChain = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
    UnableToGetIssuerCertLocally = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
    UnableToVerifyLeafSignature = X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
    CertChainTooLong = X509_V_ERR_CERT_CHAIN_TOO_LONG,
    CertRevoked = X509_V_ERR_CERT_REVOKED,
    NoIssuerPublicKey = X509_V_ERR_NO_ISSUER_PUBLIC_KEY,
    PathLengthExceed = X509_V_ERR_PATH_LENGTH_EXCEEDED,
    InvalidPurpose = X509_V_ERR_INVALID_PURPOSE,
    CertUntrusted = X509_V_ERR_CERT_UNTRUSTED,
    CertRejected = X509_V_ERR_CERT_REJECTED,
    SubjectIssuerMismatch = X509_V_ERR_SUBJECT_ISSUER_MISMATCH,
    AKIDAndSKIDMismatch = X509_V_ERR_AKID_SKID_MISMATCH,
    AKIDIssuerSerialMismatch = X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH,
    KeyUsageNoCertSign = X509_V_ERR_KEYUSAGE_NO_CERTSIGN,
    UnableToGetCRLIssuer = X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER,
    UnhandledCriticalExtension = X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION,
    KUNoCrlSign = X509_V_ERR_KEYUSAGE_NO_CRL_SIGN,
    UnhandledCriticalCRLExtension = X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION,
    InvalidNonCA = X509_V_ERR_INVALID_NON_CA,
    ProxyPathLengthExceeded = X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED,
    KeyUsageNoDigitalSignature = X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE,
    ProxyCertificatesNotAllower = X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED,
    InvalidExtension = X509_V_ERR_INVALID_EXTENSION,
    InvalidPolicyExtension = X509_V_ERR_INVALID_POLICY_EXTENSION,
    NoExplicitPolicy = X509_V_ERR_NO_EXPLICIT_POLICY,
    DifferentCRLScope = X509_V_ERR_DIFFERENT_CRL_SCOPE,
    UnsupportedExtensionFeature = X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE,
    UnnestedResource = X509_V_ERR_UNNESTED_RESOURCE,
    PermittedViolation = X509_V_ERR_PERMITTED_VIOLATION,
    ExcludedViolation = X509_V_ERR_EXCLUDED_VIOLATION,
    SubtreeMinMax = X509_V_ERR_SUBTREE_MINMAX,
    ApplicationVarification = X509_V_ERR_APPLICATION_VERIFICATION,
    UnsupportedConstraintType = X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE,
    UnsupportedConstraintSyntax = X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX,
    UnsupportedNameSyntax = X509_V_ERR_UNSUPPORTED_NAME_SYNTAX,
    CRLPathValidationError = X509_V_ERR_CRL_PATH_VALIDATION_ERROR,
    PathLoop = X509_V_ERR_PATH_LOOP,
    SuiteBInvalidVersion = X509_V_ERR_SUITE_B_INVALID_VERSION,
    SuiteBInvalidAlgorithm = X509_V_ERR_SUITE_B_INVALID_ALGORITHM,
    SuiteBInvalidCurve = X509_V_ERR_SUITE_B_INVALID_CURVE,
    SuiteBInvalidSignatureAlgorithm = X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM,
    SuiteBLOSNotAllowed = X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED,
    SuiteBCantSignP384WithP256 = X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256,
    HostnameMismatch = X509_V_ERR_HOSTNAME_MISMATCH,
    EmailMismatch = X509_V_ERR_EMAIL_MISMATCH,
    IPAddressMismatch = X509_V_ERR_IP_ADDRESS_MISMATCH,
    DANENoMatch = X509_V_ERR_DANE_NO_MATCH,
    EEKeyTooSmall = X509_V_ERR_EE_KEY_TOO_SMALL,
    CAKeyTooSmall = X509_V_ERR_CA_KEY_TOO_SMALL,
    CAMsgDigestTooWeak = X509_V_ERR_CA_MD_TOO_WEAK,
    InvalidCall = X509_V_ERR_INVALID_CALL,
    StoreLookup = X509_V_ERR_STORE_LOOKUP,
    NoValidSCTS = X509_V_ERR_NO_VALID_SCTS,
    ProxySubjectNameViolation = X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION,
    OCSPVerifyNeeded = X509_V_ERR_OCSP_VERIFY_NEEDED,
    OCSPVerifyFailed = X509_V_ERR_OCSP_VERIFY_FAILED,
    OCSPCertUnknown = X509_V_ERR_OCSP_CERT_UNKNOWN,
    UnsupportedSignatureAlgorithm = X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM,
    SignatureAlgorithmMismatch = X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH,
    InvalidCA = X509_V_ERR_INVALID_CA,
    ExplicitECParams = X509_V_ERR_EC_KEY_EXPLICIT_PARAMS,
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    SignatureAlgInconsistency = X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY,
    PathLengthInvalidForNonCA = X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA,
    PathLengthWithoutKUkeyCertSign = X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN,
    KUkeyCertSignInvalidForNonCA = X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA,
    IssuerNameEmpty = X509_V_ERR_ISSUER_NAME_EMPTY,
    SubjectNameEmpty = X509_V_ERR_SUBJECT_NAME_EMPTY,
    MissingAuthKeyID = X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER,
    MissingSubjectKeyID = X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER,
    EmptySubjectAltName = X509_V_ERR_EMPTY_SUBJECT_ALT_NAME,
    BasicConstraintsCANotCritical = X509_V_ERR_CA_BCONS_NOT_CRITICAL,
    SubjectAltNameNotCritical = X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL,
    AuthKeyIDCritical = X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL,
    SubjectKeyIDCritical = X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL,
    CACertMissingKeyUsage = X509_V_ERR_CA_CERT_MISSING_KEY_USAGE,
    ExtensionsRequireV3 = X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3,
#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)
};

std::error_code MakeErrorCode(Error e);

} // namespace snet::crypto::verify
