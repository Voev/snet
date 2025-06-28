#pragma once

#include <snet/cpp_port/span.hpp>
#include <string>
#include <vector>
#include <stdexcept>

namespace snet::filter
{

/**
 * This class represents general abstract filter objects.
 */
class Filter
{
public:
    /**
     * @return descriptive name for this filter
     */
    virtual std::string name() const = 0;

    /**
     * Write a portion of a message to this filter.
     * @param input the input as a byte array
     * @param length the length of the byte array input
     */
    virtual void write(const uint8_t input[], size_t length) = 0;

    /**
     * Start a new message. Must be closed by end_msg() before another
     * message can be started.
     */
    virtual void start_msg()
    { /* default empty */
    }

    /**
     * Notify that the current message is finished; flush buffers and
     * do end-of-message processing (if any).
     */
    virtual void end_msg()
    { /* default empty */
    }

    /**
     * Check whether this filter is an attachable filter.
     * @return true if this filter is attachable, false otherwise
     */
    virtual bool attachable()
    {
        return true;
    }

    virtual ~Filter() = default;

    Filter(const Filter&) = delete;
    Filter& operator=(const Filter&) = delete;

protected:
    /**
     * @param in some input for the filter
     * @param length the length of in
     */
    virtual void send(const uint8_t in[], size_t length)
    {
        if (!length)
        {
            return;
        }

        bool nothing_attached = true;
        for (size_t j = 0; j != total_ports(); ++j)
        {
            if (m_next[j])
            {
                if (!m_write_queue.empty())
                {
                    m_next[j]->write(m_write_queue.data(), m_write_queue.size());
                }
                m_next[j]->write(in, length);
                nothing_attached = false;
            }
        }

        if (nothing_attached)
        {
            m_write_queue.insert(m_write_queue.end(), in, in + length);
        }
        else
        {
            m_write_queue.clear();
        }
    }
    /**
     * @param in some input for the filter
     */
    void send(uint8_t in)
    {
        send(&in, 1);
    }

    /**
     * @param in some input for the filter
     */
    void send(cpp::span<const uint8_t> in)
    {
        send(in.data(), in.size());
    }

    /**
     * @param in some input for the filter
     * @param length the number of bytes of in to send
     *
     * This previously took a std::vector, for which the length field (allowing
     * using just a prefix of the vector) somewhat made sense. It makes less
     * sense now that we are using a span here; you can just use `first` to get
     * a prefix.
     */
    void send(cpp::span<const uint8_t> in, size_t length)
    {
        send(in.data(), length);
    }

    Filter()
    {
        m_next.resize(1);
        m_port_num = 0;
        m_filter_owns = 0;
        m_owned = false;
    }

private:
    /**
     * Start a new message in *this and all following filters. Only for
     * internal use, not intended for use in client applications.
     */
    void new_msg()
    {
        start_msg();
        for (size_t j = 0; j != total_ports(); ++j)
        {
            if (m_next[j])
            {
                m_next[j]->new_msg();
            }
        }
    }

    /**
     * End a new message in *this and all following filters. Only for
     * internal use, not intended for use in client applications.
     */
    void finish_msg()
    {
        end_msg();
        for (size_t j = 0; j != total_ports(); ++j)
        {
            if (m_next[j])
            {
                m_next[j]->finish_msg();
            }
        }
    }

    size_t total_ports() const
    {
        return m_next.size();
    }

    size_t current_port() const
    {
        return m_port_num;
    }

    /**
     * Set the active port
     * @param new_port the new value
     */
    void set_port(size_t new_port)
    {
        if (new_port >= total_ports())
        {
            throw std::runtime_error("Filter: Invalid port number");
        }
        m_port_num = new_port;
    }

    size_t owns() const
    {
        return m_filter_owns;
    }

    /**
     * Attach another filter to this one
     * @param f filter to attach
     */
    void attach(Filter* f)
    {
        if (f)
        {
            Filter* last = this;
            while (last->get_next())
            {
                last = last->get_next();
            }
            last->m_next[last->current_port()] = f;
        }
    }

    /**
     * @param filters the filters to set
     * @param count number of items in filters
     */
    void set_next(Filter* filters[], size_t size)
    {
        m_next.clear();

        m_port_num = 0;
        m_filter_owns = 0;

        while (size && filters && (filters[size - 1] == nullptr))
        {
            --size;
        }

        if (filters && size)
        {
            m_next.assign(filters, filters + size);
        }
    }
    Filter* get_next() const
    {
        if (m_port_num < m_next.size())
        {
            return m_next[m_port_num];
        }
        return nullptr;
    }

    std::vector<uint8_t> m_write_queue;
    std::vector<Filter*> m_next; // not owned
    size_t m_port_num, m_filter_owns;

    // true if filter belongs to a pipe --> prohibit filter sharing!
    bool m_owned;
};

} // namespace snet::filter
