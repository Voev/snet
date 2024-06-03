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
#include <snet/utils/format.hpp>

namespace snet::utils
{

namespace details
{

template <class F, class Tuple, class Extra, std::size_t... I>
constexpr decltype(auto)
apply_plus_one_impl(F&& f, Tuple&& t, Extra&& x,
                    std::index_sequence<I...> /*unused*/)
{
    return std::invoke(std::forward<F>(f),
                       std::get<I>(std::forward<Tuple>(t))...,
                       std::forward<Extra>(x));
}

template <class F, class Tuple, class Extra>
constexpr decltype(auto) apply_plus_one(F&& f, Tuple&& t, Extra&& x)
{
    return details::apply_plus_one_impl(
        std::forward<F>(f), std::forward<Tuple>(t), std::forward<Extra>(x),
        std::make_index_sequence<
            std::tuple_size_v<std::remove_reference_t<Tuple>>>{});
}

static constexpr std::string_view kSinglePrefix = "-";
static constexpr std::string_view kDoublePrefix = "--";

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

enum class OptionType
{
    NoValue,
    SingleValue,
    MultiValue
};

class ArgumentParser;

class Argument
{
    friend class ArgumentParser;
    friend auto operator<<(std::ostream& stream, const ArgumentParser& parser)
        -> std::ostream&;

public:

    Argument(std::string_view optionName, std::string_view description,
             OptionType optionType)
        : description_(description)
        , type_(optionType)
        , isRequired_(false)
        , isUsed_(false)
    {
        auto end = optionName.find_first_of(',');
        if (end == std::string_view::npos)
        {
            longName_ = optionName;
        }
        else
        {
            auto start = optionName.find_first_not_of(' ', end + 1);
            if (start == std::string_view::npos)
            {
                throw std::runtime_error("invalid option name");
            }
            longName_ = optionName.substr(0, end);
            shortName_ = optionName.substr(start);
        }
    }

    template <class F, class... Args>
    auto action(F&& callable, Args&&... bound_args)
        -> std::enable_if_t<std::is_invocable_v<F, Args..., std::string const>,
                            Argument&>
    {
        using action_type = std::conditional_t<
            std::is_void_v<std::invoke_result_t<F, Args..., std::string const>>,
            void_action, valued_action>;
        if constexpr (sizeof...(Args) == 0)
        {
            action_.emplace<action_type>(std::forward<F>(callable));
        }
        else
        {
            action_.emplace<action_type>(
                [f = std::forward<F>(callable),
                 tup = std::make_tuple(std::forward<Args>(bound_args)...)](
                    std::string const& opt) mutable {
                    return details::apply_plus_one(f, tup, opt);
                });
        }
        return *this;
    }

    template <typename Iterator> Iterator consume(Iterator start, Iterator end)
    {
        if (isUsed_)
        {
            throw std::runtime_error("duplicated option");
        }
        isUsed_ = true;

        if (type_ == OptionType::NoValue)
        {
            std::visit([](const auto& f) { f({}); }, action_);
            return start;
        }
        else
        {
            struct ActionApply
            {
                void operator()(valued_action& f)
                {
                    std::transform(first, last,
                                   std::back_inserter(self.values_), f);
                }

                void operator()(void_action& f)
                {
                    std::for_each(first, last, f);
                }

                Iterator first, last;
                Argument& self;
            };

            if (type_ == OptionType::SingleValue)
            {
                if (start == end)
                {
                    throw std::runtime_error(utils::Format(
                        "no value provided for option '{}'", longName_));
                }

                std::visit(ActionApply{start, std::next(start), *this},
                           action_);
                return std::next(start);
            }
            else
            {
                std::visit(ActionApply{start, end, *this}, action_);
                return end;
            }
        }
    }

    /*
     * @throws std::runtime_error if argument values are not valid
     */
    void validate() const
    {
        if (!isUsed_ && isRequired_)
        {
            throw std::runtime_error(
                utils::Format("'{}' must be specified", longName_));
        }
        if (isUsed_ && isRequired_ && values_.empty())
        {
            throw std::runtime_error(
                utils::Format("no value for '{}' option", longName_));
        }
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
    /*
     * Get argument value given a type
     * @throws std::logic_error in case of incompatible types
     */
    template <typename T> T get() const
    {
        if (!values_.empty())
        {
            if constexpr (details::IsContainer<T>)
            {
                return any_cast_container<T>(values_);
            }
            else
            {
                return std::any_cast<T>(values_.front());
            }
        }

        throw std::logic_error("No value provided for '" + longName_ + "'");
    }

    /*
     * Get argument value given a type.
     * @pre The object has no default value.
     * @returns The stored value if any, std::nullopt otherwise.
     */
    template <typename T> auto present() const -> std::optional<T>
    {
        if (values_.empty())
        {
            return std::nullopt;
        }
        if constexpr (details::IsContainer<T>)
        {
            return any_cast_container<T>(values_);
        }
        return std::any_cast<T>(values_.front());
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

    using valued_action = std::function<std::any(const std::string&)>;
    using void_action = std::function<void(const std::string&)>;

private:
    std::variant<valued_action, void_action> action_{
        std::in_place_type<valued_action>,
        [](const std::string& value) { return value; }};
    std::vector<std::any> values_;
    std::string longName_;
    std::optional<std::string> shortName_;
    std::string description_;
    OptionType type_;
    bool isRequired_;
    bool isUsed_;
};

class ArgumentParser
{
public:
    ArgumentParser() = default;
    ~ArgumentParser() = default;

    ArgumentParser(const ArgumentParser& other) = delete;
    ArgumentParser& operator=(const ArgumentParser& other) = delete;

    ArgumentParser(ArgumentParser&&) = delete;
    ArgumentParser& operator=(ArgumentParser&&) = delete;

    Argument& add(std::string_view name, std::string_view desc, OptionType type)
    {
        auto option = options_.emplace(std::cend(options_), name, desc, type);
        optionMap_.insert_or_assign(option->longName_, option);

        if (option->shortName_.has_value())
        {
            optionMap_.insert_or_assign(option->shortName_.value(), option);
        }
        return *option;
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

    void parse(const std::vector<std::string>& args)
    {
        auto end = std::end(args);

        for (auto arg = std::begin(args); arg != end;)
        {
            /**
             * Processing options like "--option=value"
             */
            auto assignPosition = arg->find_first_of('=');
            if (assignPosition != std::string_view::npos &&
                arg->rfind("--", 0) == 0)
            {
                auto optionName = arg->substr(0, assignPosition);
                if (optionMap_.find(optionName) != optionMap_.end())
                {
                    // This is the name of an option! Split it into two parts
                    // result.push_back(std::move(opt_name));
                    // result.push_back(arg.substr(assignPosition + 1));
                    continue;
                }
                else
                {
                    throw std::runtime_error(
                        utils::Format("unknown option: {}", optionName));
                }
            }

            if ((*arg)[0] == '-')
            {
                std::string optionName;
                if ((*arg)[1] == '-')
                {
                    optionName = arg->substr(2);
                }
                else
                {
                    optionName = arg->substr(1);
                }

                auto found = optionMap_.find(optionName);
                if (found != optionMap_.end())
                {
                    arg = found->second->consume(std::next(arg), end);
                }
                else
                {
                    throw std::runtime_error(
                        utils::Format("unknown option: {}", optionName));
                }
            }
            else
            {
                throw std::runtime_error(
                    utils::Format("unknown option: {}", *arg));
            }
        }
        parsed_ = true;
    }

    /* Getter for options with default values.
     * @throws std::logic_error if parse_args() has not been previously called
     * @throws std::logic_error if there is no such option
     * @throws std::logic_error if the option has no value
     * @throws std::bad_any_cast if the option is not of type T
     */
    template <typename T = std::string> T get(std::string_view arg_name) const
    {
        if (!parsed_)
        {
            throw std::logic_error("attempt to get value before parsing");
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
        return (*this)[arg_name].isUsed_;
    }

    /* Indexing operator. Return a reference to an Argument object
     * Used in conjunction with Argument.operator== e.g., parser["foo"] == true
     * @throws std::logic_error in case of an invalid argument name
     */
    Argument& operator[](std::string_view arg_name) const
    {
        auto it = optionMap_.find(arg_name.data());
        if (it != optionMap_.end())
        {
            return *(it->second);
        }
        throw std::logic_error("No such argument: " + std::string(arg_name));
    }

    // Format usage part of help only
    std::string help() const
    {
        std::stringstream ss;

        usage(ss);

        ss << "Options:\n";
        for (auto option : options_)
        {
            ss << details::kDoublePrefix << option.longName_;
            if (option.shortName_.has_value())
            {
                ss << " [ " << details::kSinglePrefix << option.shortName_.value() << " ]";
            }
            switch (option.type_)
            {
            case OptionType::NoValue:
                break;

            case OptionType::SingleValue:
                ss << " arg";
                break;
            case OptionType::MultiValue:
                ss << " args...";
                break;
            default:
                break;
            };

            ss << "\t" << option.description_ << "\n";
        }
        return ss.str();
    }

    void usage(std::stringstream& ss) const
    {
        ss << "Usage:\n";

        for (auto option : options_)
        {
            ss << " ";

            if(!option.isRequired_)
            {
                ss << "[ ";
            }
            ss << details::kDoublePrefix << option.longName_;
           
            switch (option.type_)
            {
            case OptionType::NoValue:
                break;
            case OptionType::SingleValue:
                ss << " arg";
                break;
            case OptionType::MultiValue:
                ss << " args...";
                break;
            default:
                break;
            };

            if(!option.isRequired_)
            {
                ss << " ]";
            }
        }
        ss << "\n\n";
    }

private:
    using ArgumentList = std::list<Argument>;
    using ArgumentIterator = ArgumentList::iterator;

    ArgumentList options_;
    std::map<std::string, ArgumentIterator> optionMap_;
    bool parsed_{false};
};

} // namespace snet::utils
