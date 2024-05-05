#pragma once

#include <algorithm>
#include <any>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <list>
#include <map>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace snet::utils
{

namespace details
{

template <typename T, typename = void>
struct HasContainerTraits : std::false_type
{
};

template <> struct HasContainerTraits<std::string> : std::false_type
{
};

template <> struct HasContainerTraits<std::string_view> : std::false_type
{
};

template <typename T>
struct HasContainerTraits<
    T, std::void_t<typename T::value_type, decltype(std::declval<T>().begin()),
                   decltype(std::declval<T>().end()),
                   decltype(std::declval<T>().size())>> : std::true_type
{
};

template <typename T>
inline constexpr bool IsContainer = HasContainerTraits<T>::value;

template <typename T> struct can_invoke_to_string
{
    template <typename U>
    static auto test(int)
        -> decltype(std::to_string(std::declval<U>()), std::true_type{});

    template <typename U> static auto test(...) -> std::false_type;

    static constexpr bool value = decltype(test<T>(0))::value;
};

} // namespace details

enum class nargs_pattern
{
    optional,
    any,
    at_least_one
};

class ArgumentParser;

class Argument
{
    friend class ArgumentParser;
    friend auto operator<<(std::ostream& stream, const ArgumentParser& parser)
        -> std::ostream&;

    template <std::size_t N, std::size_t... I>
    explicit Argument(std::string_view prefix_chars,
                      std::array<std::string_view, N>&& a,
                      std::index_sequence<I...> /*unused*/)
        : m_accepts_optional_like_value(false)
        , m_is_optional((is_optional(a[I], prefix_chars) || ...))
        , m_is_required(false)
        , m_is_repeatable(false)
        , m_is_used(false)
        , m_prefix_chars(prefix_chars)
    {
        ((void)m_names.emplace_back(a[I]), ...);
        std::sort(m_names.begin(), m_names.end(),
                  [](const auto& lhs, const auto& rhs) {
                      return lhs.size() == rhs.size() ? lhs < rhs
                                                      : lhs.size() < rhs.size();
                  });
    }

public:
    template <std::size_t N>
    explicit Argument(std::string_view prefix_chars,
                      std::array<std::string_view, N>&& a)
        : Argument(prefix_chars, std::move(a), std::make_index_sequence<N>{})
    {
    }

    Argument& help(std::string help_text)
    {
        m_help = std::move(help_text);
        return *this;
    }

    Argument& metavar(std::string metavar)
    {
        m_metavar = std::move(metavar);
        return *this;
    }

    template <typename T> Argument& default_value(T&& value)
    {
        m_num_args_range = NArgsRange{0, m_num_args_range.get_max()};

        if constexpr (std::is_convertible_v<T, std::string_view>)
        {
            m_default_value_str = std::string{std::string_view{value}};
        }
        else if constexpr (details::can_invoke_to_string<T>::value)
        {
            m_default_value_str = std::to_string(value);
        }

        m_default_value = std::forward<T>(value);
        return *this;
    }

    Argument& default_value(const char* value)
    {
        return default_value(std::string(value));
    }

    Argument& required()
    {
        m_is_required = true;
        return *this;
    }

    Argument& implicit_value(std::any value)
    {
        m_implicit_value = std::move(value);
        m_num_args_range = NArgsRange{0, 0};
        return *this;
    }

    // This is shorthand for:
    //   program.add_argument("foo")
    //     .default_value(false)
    //     .implicit_value(true)
    Argument& flag()
    {
        default_value(false);
        implicit_value(true);
        return *this;
    }

    auto& append()
    {
        m_is_repeatable = true;
        return *this;
    }

    Argument& nargs(std::size_t num_args)
    {
        m_num_args_range = NArgsRange{num_args, num_args};
        return *this;
    }

    Argument& nargs(std::size_t num_args_min, std::size_t num_args_max)
    {
        m_num_args_range = NArgsRange{num_args_min, num_args_max};
        return *this;
    }

    Argument& nargs(nargs_pattern pattern)
    {
        switch (pattern)
        {
        case nargs_pattern::optional:
            m_num_args_range = NArgsRange{0, 1};
            break;
        case nargs_pattern::any:
            m_num_args_range =
                NArgsRange{0, (std::numeric_limits<std::size_t>::max)()};
            break;
        case nargs_pattern::at_least_one:
            m_num_args_range =
                NArgsRange{1, (std::numeric_limits<std::size_t>::max)()};
            break;
        }
        return *this;
    }

    Argument& remaining()
    {
        m_accepts_optional_like_value = true;
        return nargs(nargs_pattern::any);
    }

    template <typename Iterator>
    Iterator consume(Iterator start, Iterator end,
                     std::string_view used_name = {})
    {
        if (!m_is_repeatable && m_is_used)
        {
            throw std::runtime_error("Duplicate argument");
        }
        m_is_used = true;
        m_used_name = used_name;

        const auto num_args_max = m_num_args_range.get_max();
        const auto num_args_min = m_num_args_range.get_min();
        std::size_t dist = 0;
        if (num_args_max == 0)
        {
            m_values.emplace_back(m_implicit_value);
            std::visit([](const auto& f) { f({}); }, m_action);
            return start;
        }
        if ((dist = static_cast<std::size_t>(std::distance(start, end))) >=
            num_args_min)
        {
            if (num_args_max < dist)
            {
                end = std::next(start,
                                static_cast<typename Iterator::difference_type>(
                                    num_args_max));
            }
            if (!m_accepts_optional_like_value)
            {
                end = std::find_if(start, end,
                                   std::bind(is_optional, std::placeholders::_1,
                                             m_prefix_chars));
                dist = static_cast<std::size_t>(std::distance(start, end));
                if (dist < num_args_min)
                {
                    throw std::runtime_error("Too few arguments");
                }
            }

            struct ActionApply
            {
                void operator()(valued_action& f)
                {
                    std::transform(first, last,
                                   std::back_inserter(self.m_values), f);
                }

                void operator()(void_action& f)
                {
                    std::for_each(first, last, f);
                    if (!self.m_default_value.has_value())
                    {
                        if (!self.m_accepts_optional_like_value)
                        {
                            self.m_values.resize(static_cast<std::size_t>(
                                std::distance(first, last)));
                        }
                    }
                }

                Iterator first, last;
                Argument& self;
            };
            std::visit(ActionApply{start, end, *this}, m_action);
            return end;
        }
        if (m_default_value.has_value())
        {
            return start;
        }
        throw std::runtime_error("Too few arguments for '" +
                                 std::string(m_used_name) + "'.");
    }

    /*
     * @throws std::runtime_error if argument values are not valid
     */
    void validate() const
    {
        if (m_is_optional)
        {
            // TODO: check if an implicit value was programmed for this argument
            if (!m_is_used && !m_default_value.has_value() && m_is_required)
            {
                throw_required_arg_not_used_error();
            }
            if (m_is_used && m_is_required && m_values.empty())
            {
                throw_required_arg_no_value_provided_error();
            }
        }
        else
        {
            if (!m_num_args_range.contains(m_values.size()) &&
                !m_default_value.has_value())
            {
                throw_nargs_range_validation_error();
            }
        }
    }

    std::string get_names_csv(char separator = ',') const
    {
        return std::accumulate(
            m_names.begin(), m_names.end(), std::string{""},
            [&](const std::string& result, const std::string& name) {
                return result.empty() ? name : result + separator + name;
            });
    }

    std::string get_usage_full() const
    {
        std::stringstream usage;

        usage << get_names_csv('/');
        const std::string metavar = !m_metavar.empty() ? m_metavar : "VAR";
        if (m_num_args_range.get_max() > 0)
        {
            usage << " " << metavar;
            if (m_num_args_range.get_max() > 1)
            {
                usage << "...";
            }
        }
        return usage.str();
    }

    std::string get_inline_usage() const
    {
        std::stringstream usage;
        // Find the longest variant to show in the usage string
        std::string longest_name = m_names.front();
        for (const auto& s : m_names)
        {
            if (s.size() > longest_name.size())
            {
                longest_name = s;
            }
        }
        if (!m_is_required)
        {
            usage << "[";
        }
        usage << longest_name;
        const std::string metavar = !m_metavar.empty() ? m_metavar : "VAR";
        if (m_num_args_range.get_max() > 0)
        {
            usage << " " << metavar;
            if (m_num_args_range.get_max() > 1)
            {
                usage << "...";
            }
        }
        if (!m_is_required)
        {
            usage << "]";
        }
        return usage.str();
    }

    std::size_t get_arguments_length() const
    {

        std::size_t names_size = std::accumulate(
            std::begin(m_names), std::end(m_names), std::size_t(0),
            [](const auto& sum, const auto& s) { return sum + s.size(); });

        if (is_positional(m_names.front(), m_prefix_chars))
        {
            // A set metavar means this replaces the names
            if (!m_metavar.empty())
            {
                // Indent and metavar
                return 2 + m_metavar.size();
            }

            // Indent and space-separated
            return 2 + names_size + (m_names.size() - 1);
        }
        // Is an option - include both names _and_ metavar
        // size = text + (", " between names)
        std::size_t size = names_size + 2 * (m_names.size() - 1);
        if (!m_metavar.empty() && m_num_args_range == NArgsRange{1, 1})
        {
            size += m_metavar.size() + 1;
        }
        return size + 2; // indent
    }

    friend std::ostream& operator<<(std::ostream& stream,
                                    const Argument& argument)
    {
        std::stringstream name_stream;
        name_stream << "  "; // indent
        if (argument.is_positional(argument.m_names.front(),
                                   argument.m_prefix_chars))
        {
            if (!argument.m_metavar.empty())
            {
                name_stream << argument.m_metavar;
            }
            else
            {
                // name_stream << details::join(argument.m_names.begin(),
                // argument.m_names.end(), " ");
            }
        }
        else
        {
            // name_stream << details::join(argument.m_names.begin(),
            // argument.m_names.end(), ", ");
            //  If we have a metavar, and one narg - print the metavar
            if (!argument.m_metavar.empty() &&
                argument.m_num_args_range == NArgsRange{1, 1})
            {
                name_stream << " " << argument.m_metavar;
            }
        }

        // align multiline help message
        auto stream_width = stream.width();
        auto name_padding = std::string(name_stream.str().size(), ' ');
        auto pos = std::string::size_type{};
        auto prev = std::string::size_type{};
        auto first_line = true;
        auto hspace = "  "; // minimal space between name and help message
        stream << name_stream.str();
        std::string_view help_view(argument.m_help);
        while ((pos = argument.m_help.find('\n', prev)) != std::string::npos)
        {
            auto line = help_view.substr(prev, pos - prev + 1);
            if (first_line)
            {
                stream << hspace << line;
                first_line = false;
            }
            else
            {
                stream.width(stream_width);
                stream << name_padding << hspace << line;
            }
            prev += pos - prev + 1;
        }
        if (first_line)
        {
            stream << hspace << argument.m_help;
        }
        else
        {
            auto leftover =
                help_view.substr(prev, argument.m_help.size() - prev);
            if (!leftover.empty())
            {
                stream.width(stream_width);
                stream << name_padding << hspace << leftover;
            }
        }

        // print nargs spec
        if (!argument.m_help.empty())
        {
            stream << " ";
        }
        stream << argument.m_num_args_range;

        if (argument.m_default_value.has_value() &&
            argument.m_num_args_range != NArgsRange{0, 0})
        {
            stream << "[default: "
                   << argument.m_default_value_str.value_or("no") << "]";
        }
        else if (argument.m_is_required)
        {
            stream << "[required]";
        }
        stream << "\n";
        return stream;
    }

    template <typename T> bool operator!=(const T& rhs) const
    {
        return !(*this == rhs);
    }

    /*
     * Compare to an argument value of known type
     * @throws std::logic_error in case of incompatible types
     */
    template <typename T> bool operator==(const T& rhs) const
    {
        if constexpr (!details::IsContainer<T>)
        {
            return get<T>() == rhs;
        }
        else
        {
            using ValueType = typename T::value_type;
            auto lhs = get<T>();
            return std::equal(std::begin(lhs), std::end(lhs), std::begin(rhs),
                              std::end(rhs), [](const auto& a, const auto& b) {
                                  return std::any_cast<const ValueType&>(a) ==
                                         b;
                              });
        }
    }

private:
    class NArgsRange
    {
        std::size_t m_min;
        std::size_t m_max;

    public:
        NArgsRange(std::size_t minimum, std::size_t maximum)
            : m_min(minimum)
            , m_max(maximum)
        {
            if (minimum > maximum)
            {
                throw std::logic_error(
                    "Range of number of arguments is invalid");
            }
        }

        bool contains(std::size_t value) const
        {
            return value >= m_min && value <= m_max;
        }

        bool is_exact() const
        {
            return m_min == m_max;
        }

        bool is_right_bounded() const
        {
            return m_max < (std::numeric_limits<std::size_t>::max)();
        }

        std::size_t get_min() const
        {
            return m_min;
        }

        std::size_t get_max() const
        {
            return m_max;
        }

        // Print help message
        friend auto operator<<(std::ostream& stream, const NArgsRange& range)
            -> std::ostream&
        {
            if (range.m_min == range.m_max)
            {
                if (range.m_min != 0 && range.m_min != 1)
                {
                    stream << "[nargs: " << range.m_min << "] ";
                }
            }
            else
            {
                if (range.m_max == (std::numeric_limits<std::size_t>::max)())
                {
                    stream << "[nargs: " << range.m_min << " or more] ";
                }
                else
                {
                    stream << "[nargs=" << range.m_min << ".." << range.m_max
                           << "] ";
                }
            }
            return stream;
        }

        bool operator==(const NArgsRange& rhs) const
        {
            return rhs.m_min == m_min && rhs.m_max == m_max;
        }

        bool operator!=(const NArgsRange& rhs) const
        {
            return !(*this == rhs);
        }
    };

    void throw_nargs_range_validation_error() const
    {
        std::stringstream stream;
        if (!m_used_name.empty())
        {
            stream << m_used_name << ": ";
        }
        else
        {
            stream << m_names.front() << ": ";
        }
        if (m_num_args_range.is_exact())
        {
            stream << m_num_args_range.get_min();
        }
        else if (m_num_args_range.is_right_bounded())
        {
            stream << m_num_args_range.get_min() << " to "
                   << m_num_args_range.get_max();
        }
        else
        {
            stream << m_num_args_range.get_min() << " or more";
        }
        stream << " argument(s) expected. " << m_values.size() << " provided.";
        throw std::runtime_error(stream.str());
    }

    void throw_required_arg_not_used_error() const
    {
        std::stringstream stream;
        stream << m_names.front() << ": required.";
        throw std::runtime_error(stream.str());
    }

    void throw_required_arg_no_value_provided_error() const
    {
        std::stringstream stream;
        stream << m_used_name << ": no value provided.";
        throw std::runtime_error(stream.str());
    }

    static constexpr int eof = std::char_traits<char>::eof();

    static auto lookahead(std::string_view s) -> int
    {
        if (s.empty())
        {
            return eof;
        }
        return static_cast<int>(static_cast<unsigned char>(s[0]));
    }

    static bool is_optional(std::string_view name,
                            std::string_view prefix_chars)
    {
        return !is_positional(name, prefix_chars);
    }

    /*
     * positional:
     *    _empty_
     *    '-'
     *    '-' decimal-literal
     *    !'-' anything
     */
    static bool is_positional(std::string_view name,
                              std::string_view prefix_chars)
    {
        auto first = lookahead(name);

        if (first == eof)
        {
            return true;
        }
        else if (prefix_chars.find(static_cast<char>(first)) !=
                 std::string_view::npos)
        {
            name.remove_prefix(1);
            if (name.empty())
            {
                return true;
            }
            return false;
        }
        return true;
    }

    /*
     * Get argument value given a type
     * @throws std::logic_error in case of incompatible types
     */
    template <typename T> T get() const
    {
        if (!m_values.empty())
        {
            if constexpr (details::IsContainer<T>)
            {
                return any_cast_container<T>(m_values);
            }
            else
            {
                return std::any_cast<T>(m_values.front());
            }
        }
        if (m_default_value.has_value())
        {
            return std::any_cast<T>(m_default_value);
        }
        if constexpr (details::IsContainer<T>)
        {
            if (!m_accepts_optional_like_value)
            {
                return any_cast_container<T>(m_values);
            }
        }

        throw std::logic_error("No value provided for '" + m_names.back() +
                               "'.");
    }

    /*
     * Get argument value given a type.
     * @pre The object has no default value.
     * @returns The stored value if any, std::nullopt otherwise.
     */
    template <typename T> auto present() const -> std::optional<T>
    {
        if (m_default_value.has_value())
        {
            throw std::logic_error(
                "Argument with default value always presents");
        }
        if (m_values.empty())
        {
            return std::nullopt;
        }
        if constexpr (details::IsContainer<T>)
        {
            return any_cast_container<T>(m_values);
        }
        return std::any_cast<T>(m_values.front());
    }

    template <typename T>
    static auto any_cast_container(const std::vector<std::any>& operand) -> T
    {
        using ValueType = typename T::value_type;

        T result;
        std::transform(
            std::begin(operand), std::end(operand), std::back_inserter(result),
            [](const auto& value) { return std::any_cast<ValueType>(value); });
        return result;
    }

    std::vector<std::string> m_names;
    std::string_view m_used_name;
    std::string m_help;
    std::string m_metavar;
    std::any m_default_value;
    std::optional<std::string>
        m_default_value_str; // used for checking default_value against choices
    std::any m_implicit_value;
    using valued_action = std::function<std::any(const std::string&)>;
    using void_action = std::function<void(const std::string&)>;
    std::variant<valued_action, void_action> m_action{
        std::in_place_type<valued_action>,
        [](const std::string& value) { return value; }};
    std::vector<std::any> m_values;
    NArgsRange m_num_args_range{1, 1};
    // Bit field of bool values. Set default value in ctor.
    bool m_accepts_optional_like_value : 1;
    bool m_is_optional : 1;
    bool m_is_required : 1;
    bool m_is_repeatable : 1;
    bool m_is_used : 1;
    std::string_view m_prefix_chars; // ArgumentParser has the prefix_chars
};

class ArgumentParser
{
public:
    ArgumentParser() = default;

    ~ArgumentParser() = default;

    // ArgumentParser is meant to be used in a single function.
    // Setup everything and parse arguments in one place.
    //
    // ArgumentParser internally uses std::string_views,
    // references, iterators, etc.
    // Many of these elements become invalidated after a copy or move.
    ArgumentParser(const ArgumentParser& other) = delete;
    ArgumentParser& operator=(const ArgumentParser& other) = delete;
    ArgumentParser(ArgumentParser&&) noexcept = delete;
    ArgumentParser& operator=(ArgumentParser&&) = delete;

    // Parameter packing
    // Call add_argument with variadic number of string arguments
    template <typename... Targs> Argument& add_argument(Targs... f_args)
    {
        using array_of_sv = std::array<std::string_view, sizeof...(Targs)>;
        auto argument = m_optional_arguments.emplace(
            std::cend(m_optional_arguments), m_prefix_chars,
            array_of_sv{f_args...});

        index_argument(argument);
        return *argument;
    }

    /* Getter for arguments and subparsers.
     * @throws std::logic_error in case of an invalid argument or subparser name
     */
    template <typename T = Argument> T& at(std::string_view name)
    {
        if constexpr (std::is_same_v<T, Argument>)
        {
            return (*this)[name];
        }
    }

    ArgumentParser& set_prefix_chars(std::string prefix_chars)
    {
        m_prefix_chars = std::move(prefix_chars);
        return *this;
    }

    ArgumentParser& set_assign_chars(std::string assign_chars)
    {
        m_assign_chars = std::move(assign_chars);
        return *this;
    }

    /* Call parse_args_internal - which does all the work
     * Then, validate the parsed arguments
     * This variant is used mainly for testing
     * @throws std::runtime_error in case of any invalid argument
     */
    void parse_args(const std::vector<std::string>& arguments)
    {
        parse_args_internal(arguments);
        // Check if all arguments are parsed
        for ([[maybe_unused]] const auto& [unused, argument] : m_argument_map)
        {
            argument->validate();
        }
    }

    /* Main entry point for parsing command-line arguments using this
     * ArgumentParser
     * @throws std::runtime_error in case of any invalid argument
     */
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
    void parse_args(int argc, const char* const argv[])
    {
        parse_args({argv + 1, argv + argc});
    }

    /* Getter for options with default values.
     * @throws std::logic_error if parse_args() has not been previously called
     * @throws std::logic_error if there is no such option
     * @throws std::logic_error if the option has no value
     * @throws std::bad_any_cast if the option is not of type T
     */
    template <typename T = std::string> T get(std::string_view arg_name) const
    {
        if (!m_is_parsed)
        {
            throw std::logic_error(
                "Nothing parsed, no arguments are available.");
        }
        return (*this)[arg_name].get<T>();
    }

    /* Getter for options without default values.
     * @pre The option has no default value.
     * @throws std::logic_error if there is no such option
     * @throws std::bad_any_cast if the option is not of type T
     */
    template <typename T = std::string>
    auto present(std::string_view arg_name) const -> std::optional<T>
    {
        return (*this)[arg_name].present<T>();
    }

    /* Getter that returns true for user-supplied options. Returns false if not
     * user-supplied, even with a default value.
     */
    auto is_used(std::string_view arg_name) const
    {
        return (*this)[arg_name].m_is_used;
    }

    /* Indexing operator. Return a reference to an Argument object
     * Used in conjunction with Argument.operator== e.g., parser["foo"] == true
     * @throws std::logic_error in case of an invalid argument name
     */
    Argument& operator[](std::string_view arg_name) const
    {
        auto it = m_argument_map.find(arg_name);
        if (it != m_argument_map.end())
        {
            return *(it->second);
        }
        if (!is_valid_prefix_char(arg_name.front()))
        {
            std::string name(arg_name);
            const auto legal_prefix_char = get_any_valid_prefix_char();
            const auto prefix = std::string(1, legal_prefix_char);

            // "-" + arg_name
            name = prefix + name;
            it = m_argument_map.find(name);
            if (it != m_argument_map.end())
            {
                return *(it->second);
            }
            // "--" + arg_name
            name = prefix + name;
            it = m_argument_map.find(name);
            if (it != m_argument_map.end())
            {
                return *(it->second);
            }
        }
        throw std::logic_error("No such argument: " + std::string(arg_name));
    }

    // Print help message
    friend auto operator<<(std::ostream& stream, const ArgumentParser& parser)
        -> std::ostream&
    {
        stream.setf(std::ios_base::left);

        auto longest_arg_length = parser.get_length_of_longest_argument();

        stream << parser.usage() << "\n\n";

        for (const auto& argument : parser.m_optional_arguments)
        {
            stream.width(static_cast<std::streamsize>(longest_arg_length));
            stream << argument;
        }

        return stream;
    }

    // Format help message
    auto help() const -> std::stringstream
    {
        std::stringstream out;
        out << *this;
        return out;
    }

    // Format usage part of help only
    auto usage() const -> std::string
    {
        std::stringstream stream;

        // Add any options inline here
        for (const auto& argument : this->m_optional_arguments)
        {
            stream << " " << argument.get_inline_usage();
        }

        return stream.str();
    }

private:
    bool is_valid_prefix_char(char c) const
    {
        return m_prefix_chars.find(c) != std::string::npos;
    }

    char get_any_valid_prefix_char() const
    {
        return m_prefix_chars[0];
    }

    /*
     * Pre-process this argument list. Anything starting with "--", that
     * contains an =, where the prefix before the = has an entry in the
     * options table, should be split.
     */
    std::vector<std::string>
    preprocess_arguments(const std::vector<std::string>& raw_arguments) const
    {
        std::vector<std::string> arguments{};
        for (const auto& arg : raw_arguments)
        {

            const auto argument_starts_with_prefix_chars =
                [this](const std::string& a) -> bool {
                if (!a.empty())
                {

                    const auto legal_prefix = [this](char c) -> bool {
                        return m_prefix_chars.find(c) != std::string::npos;
                    };

                    // Slash '/' is not a legal prefix char
                    // For all other characters, only support long arguments
                    // i.e., the argument must start with 2 prefix chars, e.g,
                    // '--foo' e,g, './test --foo=Bar -DARG=yes'
                    if (a.size() > 1)
                    {
                        return (legal_prefix(a[0]) && legal_prefix(a[1]));
                    }
                }
                return false;
            };

            // Check that:
            // - We don't have an argument named exactly this
            // - The argument starts with a prefix char, e.g., "--"
            // - The argument contains an assign char, e.g., "="
            auto assign_char_pos = arg.find_first_of(m_assign_chars);

            if (m_argument_map.find(arg) == m_argument_map.end() &&
                argument_starts_with_prefix_chars(arg) &&
                assign_char_pos != std::string::npos)
            {
                // Get the name of the potential option, and check it exists
                std::string opt_name = arg.substr(0, assign_char_pos);
                if (m_argument_map.find(opt_name) != m_argument_map.end())
                {
                    // This is the name of an option! Split it into two parts
                    arguments.push_back(std::move(opt_name));
                    arguments.push_back(arg.substr(assign_char_pos + 1));
                    continue;
                }
            }
            // If we've fallen through to here, then it's a standard argument
            arguments.push_back(arg);
        }
        return arguments;
    }

    /*
     * @throws std::runtime_error in case of any invalid argument
     */
    void parse_args_internal(const std::vector<std::string>& raw_arguments)
    {
        auto arguments = preprocess_arguments(raw_arguments);
        auto end = std::end(arguments);
        
        for (auto it = std::begin(arguments); it != end;)
        {
            const auto& current_argument = *it;

            auto arg_map_it = m_argument_map.find(current_argument);
            if (arg_map_it != m_argument_map.end())
            {
                auto argument = arg_map_it->second;
                it = argument->consume(std::next(it), end, arg_map_it->first);
            }
            else if (const auto& compound_arg = current_argument;
                     compound_arg.size() > 1 &&
                     is_valid_prefix_char(compound_arg[0]) &&
                     !is_valid_prefix_char(compound_arg[1]))
            {
                ++it;
                for (std::size_t j = 1; j < compound_arg.size(); j++)
                {
                    auto hypothetical_arg = std::string{'-', compound_arg[j]};
                    auto arg_map_it2 = m_argument_map.find(hypothetical_arg);
                    if (arg_map_it2 != m_argument_map.end())
                    {
                        auto argument = arg_map_it2->second;
                        it = argument->consume(it, end, arg_map_it2->first);
                    }
                    else
                    {
                        throw std::runtime_error("Unknown argument: " +
                                                 current_argument);
                    }
                }
            }
            else
            {
                throw std::runtime_error("Unknown argument: " +
                                         current_argument);
            }
        }
        m_is_parsed = true;
    }

    // Used by print_help.
    std::size_t get_length_of_longest_argument() const
    {
        if (m_argument_map.empty())
        {
            return 0;
        }
        std::size_t max_size = 0;
        for ([[maybe_unused]] const auto& [unused, argument] : m_argument_map)
        {
            max_size = std::max<std::size_t>(max_size,
                                             argument->get_arguments_length());
        }
        return max_size;
    }

    using argument_it = std::list<Argument>::iterator;
    using argument_parser_it =
        std::list<std::reference_wrapper<ArgumentParser>>::iterator;

    void index_argument(argument_it it)
    {
        for (const auto& name : std::as_const(it->m_names))
        {
            m_argument_map.insert_or_assign(name, it);
        }
    }

    std::string m_prefix_chars{"-"};
    std::string m_assign_chars{"="};
    bool m_is_parsed = false;
    std::list<Argument> m_optional_arguments;
    std::map<std::string_view, argument_it> m_argument_map;
};

} // namespace snet::utils