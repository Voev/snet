#pragma once
#include <span>
#include <string>
#include <vector>
#include <casket/utils/exception.hpp>
#include <casket/utils/format.hpp>
#include <snet/utils/load_store.hpp>

namespace snet::utils
{

class DataReader final
{
public:
    DataReader(const char* type, std::span<const uint8_t> buf_in)
        : m_typename(type)
        , m_buf(buf_in)
        , m_offset(0)
    {
    }

    void assert_done() const
    {
        if (has_remaining())
        {
            throw_decode_error("Extra bytes at end of message");
        }
    }

    size_t read_so_far() const
    {
        return m_offset;
    }

    size_t remaining_bytes() const
    {
        return m_buf.size() - m_offset;
    }

    bool has_remaining() const
    {
        return (remaining_bytes() > 0);
    }

    std::span<const uint8_t> get_span_remaining()
    {
        return {m_buf.begin() + m_offset, m_buf.end()};
    }

    std::vector<uint8_t> get_remaining()
    {
        return std::vector<uint8_t>(m_buf.begin() + m_offset, m_buf.end());
    }

    std::vector<uint8_t> get_data_read_so_far()
    {
        return std::vector<uint8_t>(m_buf.begin(), m_buf.begin() + m_offset);
    }

    void discard_next(size_t bytes)
    {
        assert_at_least(bytes);
        m_offset += bytes;
    }

    uint32_t get_uint32_t()
    {
        assert_at_least(4);
        uint32_t result = snet::utils::make_uint32(m_buf[m_offset], m_buf[m_offset + 1],
                                                   m_buf[m_offset + 2], m_buf[m_offset + 3]);
        m_offset += 4;
        return result;
    }

    uint32_t get_uint24_t()
    {
        assert_at_least(3);
        uint32_t result =
            snet::utils::make_uint32(0, m_buf[m_offset], m_buf[m_offset + 1], m_buf[m_offset + 2]);
        m_offset += 3;
        return result;
    }

    uint16_t get_uint16_t()
    {
        assert_at_least(2);
        uint16_t result = snet::utils::make_uint16(m_buf[m_offset], m_buf[m_offset + 1]);
        m_offset += 2;
        return result;
    }

    uint16_t peek_uint16_t() const
    {
        assert_at_least(2);
        return snet::utils::make_uint16(m_buf[m_offset], m_buf[m_offset + 1]);
    }

    uint8_t get_byte()
    {
        assert_at_least(1);
        uint8_t result = m_buf[m_offset];
        m_offset += 1;
        return result;
    }

    template <typename T, typename Container>
    Container get_elem(size_t num_elems)
    {
        assert_at_least(num_elems * sizeof(T));

        Container result(num_elems);

        for (size_t i = 0; i != num_elems; ++i)
        {
            result[i] = snet::utils::load_be<T>(&m_buf[m_offset], i);
        }

        m_offset += num_elems * sizeof(T);

        return result;
    }

    template <typename T>
    std::vector<T> get_range(size_t len_bytes, size_t min_elems, size_t max_elems)
    {
        const size_t num_elems = get_num_elems(len_bytes, sizeof(T), min_elems, max_elems);

        return get_elem<T, std::vector<T>>(num_elems);
    }

    template <typename T>
    std::vector<T> get_range_vector(size_t len_bytes, size_t min_elems, size_t max_elems)
    {
        const size_t num_elems = get_num_elems(len_bytes, sizeof(T), min_elems, max_elems);

        return get_elem<T, std::vector<T>>(num_elems);
    }

    std::string get_string(size_t len_bytes, size_t min_bytes, size_t max_bytes)
    {
        std::vector<uint8_t> v = get_range_vector<uint8_t>(len_bytes, min_bytes, max_bytes);
        return std::string(v.begin(), v.end());
    }

    template <typename T>
    std::vector<T> get_fixed(size_t size)
    {
        return get_elem<T, std::vector<T>>(size);
    }

    template <typename T>
    std::span<const T> get_span_fixed(size_t numElems)
    {
        assert_at_least(numElems * sizeof(T));

        std::span<const T> result(reinterpret_cast<const T*>(&m_buf[m_offset]), numElems);

        m_offset += numElems * sizeof(T);

        return result;
    }

    std::vector<uint8_t> get_tls_length_value(size_t lenBytes)
    {
        return get_fixed<uint8_t>(get_length_field(lenBytes));
    }

    std::span<const uint8_t> get_span_length_and_value(size_t lenBytes)
    {
        return get_span_fixed<const uint8_t>(get_length_field(lenBytes));
    }

private:
    size_t get_length_field(size_t len_bytes)
    {
        assert_at_least(len_bytes);

        if (len_bytes == 1)
        {
            return get_byte();
        }
        else if (len_bytes == 2)
        {
            return get_uint16_t();
        }
        else if (len_bytes == 3)
        {
            return get_uint24_t();
        }

        throw_decode_error("Bad length size");
    }

    size_t get_num_elems(size_t len_bytes, size_t T_size, size_t min_elems, size_t max_elems)
    {
        const size_t byte_length = get_length_field(len_bytes);

        if (byte_length % T_size != 0)
        {
            throw_decode_error("Size isn't multiple of T");
        }

        const size_t num_elems = byte_length / T_size;

        if (num_elems < min_elems || num_elems > max_elems)
        {
            throw_decode_error("Length field outside parameters");
        }

        return num_elems;
    }

    void assert_at_least(size_t n) const
    {
        if (m_buf.size() - m_offset < n)
        {
            throw_decode_error("Expected " + std::to_string(n) + " bytes remaining, only " +
                               std::to_string(m_buf.size() - m_offset) + " left");
        }
    }

    [[noreturn]] void throw_decode_error(std::string_view why) const
    {
        throw casket::utils::RuntimeError(casket::utils::format("Invalid {}: {}", m_typename, why));
    }

    const char* m_typename;
    std::span<const uint8_t> m_buf;
    size_t m_offset;
};

} // namespace snet::utils
