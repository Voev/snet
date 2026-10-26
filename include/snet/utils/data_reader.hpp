#pragma once

#include <vector>
#include <string>
#include <cstring>

#include <casket/nonstd/span.hpp>
#include <casket/utils/exception.hpp>
#include <casket/utils/format.hpp>
#include <casket/utils/load_store.hpp>

#include <snet/utils/decode_error.hpp>

namespace snet::utils
{

class DataReader final
{
public:
    DataReader(const char* type, nonstd::span<const uint8_t> buf_in)
        : m_typename(type)
        , m_buf(buf_in)
        , m_offset(0)
        , error_(DecodeError::None)
    {
    }

    DataReader(const DataReader&) = delete;

    DataReader& operator=(const DataReader&) = delete;

    bool ok() const noexcept
    {
        return error_ == DecodeError::None;
    }

    explicit operator bool() const noexcept
    {
        return ok();
    }

    void set_error(DecodeError e) noexcept
    {
        if (error_ == DecodeError::None)
        {
            error_ = e;
        }
    }

    DecodeError error() const noexcept
    {
        return error_;
    }

    DecodeError take_error() noexcept
    {
        const auto e = error_;
        error_ = DecodeError::None;
        return e;
    }

    std::error_code take_ec() noexcept
    {
        return make_error_code(take_error());
    }

    void assert_done() noexcept
    {
        if (has_remaining())
        {
            set_error(DecodeError::TrailingBytes);
        }
    }

    size_t read_so_far() const noexcept
    {
        return m_offset;
    }

    size_t remaining_bytes() const noexcept
    {
        return m_buf.size() - m_offset;
    }

    bool has_remaining() const noexcept
    {
        return m_offset < m_buf.size();
    }

    void discard_next(size_t n) noexcept
    {
        if (!at_least(n))
        {
            return;
        }
        m_offset += n;
    }

    uint8_t get_byte() noexcept
    {
        if (!at_least(1))
        {
            return 0;
        }
        return m_buf[m_offset++];
    }

    uint16_t get_uint16_t()
    {
        if (!at_least(2))
        {
            return 0;
        }
        uint16_t result = casket::make_uint16(m_buf[m_offset], m_buf[m_offset + 1]);
        m_offset += 2;
        return result;
    }

    uint16_t peek_uint16_t() const noexcept
    {
        if (!at_least_const(2))
        {
            return 0;
        }
        return casket::make_uint16(m_buf[m_offset], m_buf[m_offset + 1]);
    }

    uint32_t get_uint24_t() noexcept
    {
        if (!at_least(3))
        {
            return 0;
        }
        uint32_t result = casket::make_uint32(0, m_buf[m_offset], m_buf[m_offset + 1], m_buf[m_offset + 2]);
        m_offset += 3;
        return result;
    }

    uint32_t get_uint32_t()
    {
        if (!at_least_const(4))
        {
            return 0;
        }
        uint32_t result =
            casket::make_uint32(m_buf[m_offset], m_buf[m_offset + 1], m_buf[m_offset + 2], m_buf[m_offset + 3]);
        m_offset += 4;
        return result;
    }

    nonstd::span<const uint8_t> get_span_fixed(size_t n) noexcept
    {
        if (!at_least(n))
            return {};
        auto s = nonstd::span<const uint8_t>(m_buf.data() + m_offset, n);
        m_offset += n;
        return s;
    }

    nonstd::span<const uint8_t> get_span_remaining() noexcept
    {
        auto s = nonstd::span<const uint8_t>(m_buf.data() + m_offset, m_buf.size() - m_offset);
        m_offset = m_buf.size();
        return s;
    }

    nonstd::span<const uint8_t> get_span(size_t lenBytes, size_t minElems, size_t maxElems) noexcept
    {
        const size_t n = get_length_field(lenBytes, minElems, maxElems);
        return get_span_fixed(n);
    }

    nonstd::span<const uint8_t> get_span_length_and_value(size_t lenBytes) noexcept
    {
        const size_t n = get_length_field(lenBytes, 0, remaining_bytes());
        return get_span_fixed(n);
    }

    nonstd::string_view get_string_view(size_t len_bytes, size_t min_b, size_t max_b) noexcept
    {
        const size_t n = get_length_field(len_bytes, min_b, max_b);
        if (error_ != DecodeError::None)
            return {};
        auto s = nonstd::string_view(reinterpret_cast<const char*>(m_buf.data() + m_offset), n);
        m_offset += n;
        return s;
    }

    bool get_fixed_into(size_t n, std::vector<uint8_t>& out) noexcept
    {
        if (!at_least(n))
            return false;
        if (!resize_guarded(out, n))
            return false;
        std::memcpy(out.data(), m_buf.data() + m_offset, n);
        m_offset += n;
        return true;
    }

    bool get_tls_length_value_into(size_t len_bytes, std::vector<uint8_t>& out) noexcept
    {
        const size_t n = get_length_field(len_bytes, 0, remaining_bytes());
        if (error_ != DecodeError::None)
            return false;
        return get_fixed_into(n, out);
    }

    template <typename T>
    bool get_elem_into(size_t num_elems, std::vector<T>& out) noexcept
    {
        if (!at_least(num_elems * sizeof(T)))
            return false;
        if (!resize_guarded(out, num_elems))
            return false;

        const uint8_t* p = m_buf.data() + m_offset;
        for (size_t i = 0; i < num_elems; ++i, p += sizeof(T))
        {
            out[i] = casket::load_be<T>(p);
        }
        m_offset += num_elems * sizeof(T);
        return true;
    }

    template <typename T>
    bool get_range_into(size_t len_bytes, size_t min_elems, size_t max_elems, std::vector<T>& out) noexcept
    {
        const size_t bytes = get_length_field(len_bytes, 0, remaining_bytes());
        if (error_ != DecodeError::None)
            return false;
        if (bytes % sizeof(T))
        {
            set_error(DecodeError::SizeNotMultiple);
            return false;
        }
        const size_t n = bytes / sizeof(T);
        if (n < min_elems || n > max_elems)
        {
            set_error(DecodeError::LengthOutOfRange);
            return false;
        }
        return get_elem_into<T>(n, out);
    }

private:
    size_t get_length_field(size_t len_bytes, size_t min_b, size_t max_b) noexcept
    {
        if (!at_least(len_bytes))
        {
            return 0;
        }

        size_t n = 0;
        switch (len_bytes)
        {
        case 1:
            n = m_buf[m_offset];
            break;
        case 2:
            n = casket::make_uint16(m_buf[m_offset], m_buf[m_offset + 1]);
            break;
        case 3:
            n = casket::make_uint32(0, m_buf[m_offset], m_buf[m_offset + 1], m_buf[m_offset + 2]);
            break;
        default:
            set_error(DecodeError::BadLengthSize);
            return 0;
        }
        m_offset += len_bytes;
        if (n < min_b || n > max_b)
        {
            set_error(DecodeError::LengthOutOfRange);
            return 0;
        }
        return n;
    }

    template <typename T>
    bool resize_guarded(std::vector<T>& out, size_t n) noexcept
    {
        if (n <= out.capacity())
        {
            out.resize(n);
            return true;
        }
        if (n > out.max_size())
        {
            set_error(DecodeError::LengthOutOfRange);
            return false;
        }
        try
        {
            out.resize(n);
            return true;
        }
        catch (...)
        {
            set_error(DecodeError::AllocationFailed);
            return false;
        }
    }

    bool at_least(size_t n) noexcept
    {
        if (remaining_bytes() < n)
        {
            set_error(DecodeError::NotEnoughBytes);
            return false;
        }
        return true;
    }

    bool at_least_const(size_t n) const noexcept
    {
        return remaining_bytes() >= n;
    }

    const char* m_typename;
    nonstd::span<const uint8_t> m_buf;
    size_t m_offset;
    DecodeError error_;
};

} // namespace snet::utils
