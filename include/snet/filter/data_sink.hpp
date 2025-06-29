#pragma once
#include <iosfwd>
#include <fstream>
#include <memory>
#include <snet/filter/filter.hpp>
#include <casket/utils/exception.hpp>

namespace snet::filter
{

class DataSink : public Filter
{
public:
    bool attachable() override
    {
        return false;
    }

    DataSink() = default;
    ~DataSink() = default;

    DataSink& operator=(const DataSink&) = delete;
    DataSink(const DataSink&) = delete;
};

/**
 * This class represents a data sink which writes its output to a stream.
 */
class DataSinkStream final : public DataSink
{
public:
    /**
     * Construct a DataSink_Stream from a stream.
     * @param stream the stream to write to
     * @param name identifier
     */
    DataSinkStream(std::ostream& stream, std::string_view name = "<std::ostream>")
        : m_identifier(name)
        , m_sink(stream)
    {
    }

    std::string name() const override
    {
        return m_identifier;
    }

    /**
     * Construct a DataSink_Stream from a filesystem path name.
     * @param pathname the name of the file to open a stream to
     * @param use_binary indicates whether to treat the file
     * as a binary file or not
     */
    DataSinkStream(std::string_view pathname, bool use_binary = false)
        : m_identifier(pathname)
        , m_sink_memory(std::make_unique<std::ofstream>(
              std::string(pathname), use_binary ? std::ios::binary : std::ios::out))
        , m_sink(*m_sink_memory)
    {
        casket::ThrowIfFalse(m_sink.good(), "DataSink_Stream: Failure opening path '{}'",
                                    pathname);
    }

    void write(const uint8_t* out, size_t length) override
    {
        m_sink.write((char*)out, length);
        casket::ThrowIfFalse(m_sink.good(), "DataSink_Stream: Failure writing to {}",
                                    m_identifier);
    }

    void end_msg() override
    {
        m_sink.flush();
    }

    ~DataSinkStream() noexcept = default;

private:
    const std::string m_identifier;
    std::unique_ptr<std::ostream> m_sink_memory;
    std::ostream& m_sink;
};

} // namespace snet::filter