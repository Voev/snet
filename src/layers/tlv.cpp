#include <snet/layers/tlv.hpp>

#include <snet/utils/endianness.hpp>

using namespace snet::utils;

namespace snet::layers
{

static int char2int(char input)
{
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    return -1;
}

size_t hexStringToByteArray(const std::string& hexString, uint8_t* resultByteArr,
                            size_t resultByteArrSize)
{
    if (hexString.size() % 2 != 0)
    {
        return 0;
    }

    memset(resultByteArr, 0, resultByteArrSize);
    for (size_t i = 0; i < hexString.length(); i += 2)
    {
        if (i >= resultByteArrSize * 2)
            return resultByteArrSize;

        int firstChar = char2int(hexString[i]);
        int secondChar = char2int(hexString[i + 1]);
        if (firstChar < 0 || secondChar < 0)
        {
            resultByteArr[0] = '\0';
            return 0;
        }

        resultByteArr[i / 2] = (firstChar << 4) | secondChar;
    }

    return hexString.length() / 2;
}

TLVRecordBuilder::TLVRecordBuilder()
{
    m_RecType = 0;
    m_RecValueLen = 0;
    m_RecValue = nullptr;
}

TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, const uint8_t* recValue, uint8_t recValueLen)
{
    init(recType, recValue, recValueLen);
}

TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, uint8_t recValue)
{
    init(recType, &recValue, sizeof(uint8_t));
}

TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, uint16_t recValue)
{
    recValue = host_to_be(recValue);
    init(recType, (uint8_t*)&recValue, sizeof(uint16_t));
}

TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, uint32_t recValue)
{
    recValue = host_to_be(recValue);
    init(recType, (uint8_t*)&recValue, sizeof(uint32_t));
}

TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, const ip::IPv4Address& recValue)
{
    uint32_t recIntValue = recValue.toUint();
    init(recType, (uint8_t*)&recIntValue, sizeof(uint32_t));
}

TLVRecordBuilder::TLVRecordBuilder(uint32_t recType, const std::string& recValue,
                                   bool valueIsHexString)
{
    m_RecType = 0;
    m_RecValueLen = 0;
    m_RecValue = nullptr;

    if (valueIsHexString)
    {
        uint8_t recValueByteArr[512];
        size_t byteArraySize = hexStringToByteArray(recValue, recValueByteArr, 512);
        if (byteArraySize > 0)
        {
            init(recType, recValueByteArr, byteArraySize);
        }
    }
    else
    {
        uint8_t* recValueByteArr = (uint8_t*)recValue.c_str();
        init(recType, recValueByteArr, recValue.length());
    }
}

void TLVRecordBuilder::copyData(const TLVRecordBuilder& other)
{
    m_RecType = other.m_RecType;
    m_RecValueLen = other.m_RecValueLen;
    m_RecValue = nullptr;
    if (other.m_RecValue != nullptr)
    {
        m_RecValue = new uint8_t[m_RecValueLen];
        memcpy(m_RecValue, other.m_RecValue, m_RecValueLen);
    }
}

TLVRecordBuilder::TLVRecordBuilder(const TLVRecordBuilder& other)
{
    copyData(other);
}

TLVRecordBuilder& TLVRecordBuilder::operator=(const TLVRecordBuilder& other)
{
    if (m_RecValue != nullptr)
    {
        delete[] m_RecValue;
        m_RecValue = nullptr;
    }

    copyData(other);

    return *this;
}

TLVRecordBuilder::~TLVRecordBuilder()
{
    if (m_RecValue != nullptr)
        delete[] m_RecValue;
}

void TLVRecordBuilder::init(uint32_t recType, const uint8_t* recValue, size_t recValueLen)
{
    m_RecType = recType;
    m_RecValueLen = recValueLen;
    m_RecValue = new uint8_t[recValueLen];
    if (recValue != nullptr)
        memcpy(m_RecValue, recValue, recValueLen);
    else
        memset(m_RecValue, 0, recValueLen);
}

} // namespace snet::layers
