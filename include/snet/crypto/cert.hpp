#pragma once
#include <ctime>
#include <string_view>
#include <filesystem>
#include <snet/crypto/pointers.hpp>

namespace snet::crypto::cert
{

CertPtr shallowCopy(Cert* cert);

CertPtr deepCopy(Cert* cert);

bool isEqual(const Cert* op1, const Cert* op2);

CertVersion version(Cert* cert);

CertNamePtr subjectName(Cert* cert);

CertNamePtr issuerName(Cert* cert);

BigNumPtr serialNumber(Cert* cert);

KeyPtr publicKey(Cert* cert);

std::time_t notBefore(Cert* cert);

std::time_t notAfter(Cert* cert);

CertPtr fromStorage(std::string_view uri);

CertPtr fromFile(const std::filesystem::path& path);

CertPtr fromBio(Bio* bio, Encoding encoding = Encoding::PEM);

void toBio(Cert* cert, Bio* bio, Encoding encoding = Encoding::PEM);

} // namespace snet::crypto::cert