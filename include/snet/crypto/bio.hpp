#include <limits>
#include <vector>
#include <array>
#include <filesystem>
#include <openssl/bio.h>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

class BioTraits
{
    static constexpr size_t kBufferSize{4096};

public:
    static inline BioPtr openFile(const std::filesystem::path& path, const char* mode)
    {
        BioPtr result{BIO_new_file(path.c_str(), mode)};
        ThrowIfTrue(result == nullptr);
        return result;
    }

    static inline BioPtr createMemoryBuffer()
    {
        BioPtr result{BIO_new(BIO_s_mem())};
        ThrowIfTrue(result == nullptr);
        return result;
    }

    static inline BioPtr createMemoryReader(const uint8_t* data, size_t size)
    {
        constexpr auto limit = std::numeric_limits<int>::max();
        BioPtr bio{BIO_new_mem_buf(data, (size > limit ? limit : size))};
        ThrowIfTrue(bio == nullptr);
        return bio;
    }

    inline BioPtr createBase64Filter(bool noNewLine = false)
    {
        BioPtr bio{BIO_new(BIO_f_base64())};
        ThrowIfTrue(bio == nullptr);
        if (noNewLine)
        {
            BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        }
        return bio;
    }

    static inline size_t writeData(Bio* bio, const uint8_t* data, size_t length)
    {
        size_t writtenBytesLen{0};
        ThrowIfFalse(BIO_write_ex(bio, data, length, &writtenBytesLen));
        return writtenBytesLen;
    }

    static inline size_t readData(Bio* bio, uint8_t* data, size_t length)
    {
        size_t readedBytesLen{0};
        ThrowIfFalse(0 < BIO_read_ex(bio, data, length, &readedBytesLen));
        return readedBytesLen;
    }

    static inline std::vector<uint8_t> readAllData(Bio* bio)
    {
        std::vector<uint8_t> data;
        std::array<uint8_t, kBufferSize> buffer{};
        size_t bytesRead;

        while (!BIO_eof(bio) && (bytesRead = readData(bio, buffer.data(), buffer.size())) > 0)
        {
            data.insert(data.end(), buffer.data(), buffer.data() + bytesRead);
        }

        return data;
    }

    static inline std::string readAllAsString(Bio* bio)
    {
        std::string data;
        std::array<char, kBufferSize> buffer{};
        size_t bytesRead;

        while (!BIO_eof(bio) && (bytesRead = readData(bio, (uint8_t*)buffer.data(), buffer.size())) > 0)
        {
            data.append(buffer.data(), bytesRead);
        }

        return data;
    }

    static inline std::vector<uint8_t> getMemoryData(Bio* bio)
    {
        uint8_t* data{nullptr};
        auto length = BIO_get_mem_data(bio, &data);
        ThrowIfTrue(data == nullptr, "invalid pointer");
        return std::vector(data, data + length);
    }

    static inline std::string getMemoryDataAsString(Bio* bio)
    {
        char* data{nullptr};
        auto length = BIO_get_mem_data(bio, &data);
        ThrowIfTrue(data == nullptr, "invalid pointer");
        return std::string(data, length);
    }

    static inline void attachFilter(BioPtr& baseBio, BioPtr&& filterBio)
    {
        baseBio.reset(BIO_push(filterBio.release(), baseBio.release()));
    }

    static inline void reset(Bio* bio)
    {
        BIO_reset(bio);
    }

    static inline void flush(Bio* bio)
    {
        ThrowIfFalse(0 < BIO_flush(bio));
    }
};

} // namespace snet::crypto