#pragma once

#include <algorithm>
#include <any>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace snet::opt
{

namespace detail
{

class ValueSemantic
{
public:
    virtual ~ValueSemantic() = default;

    virtual void parse(std::any& value,
                       const std::vector<std::string_view>& args) = 0;

    virtual void notify(const std::any& valueStore) const = 0;

    virtual std::size_t minTokens() const = 0;

    virtual std::size_t maxTokens() const = 0;
};

class UntypedValue : public ValueSemantic
{
public:
    void parse(std::any&, const std::vector<std::string_view>&) override
    {
    }

    void notify(const std::any&) const override
    {
    }

    std::size_t minTokens() const override
    {
        return 0U;
    }

    std::size_t maxTokens() const override
    {
        return 0U;
    };
};

template <typename T> class TypedValue : public ValueSemantic
{
public:
    TypedValue(T* typedPtr)
        : typedPtr_(typedPtr)
    {
    }

public:
    void parse(std::any& value,
               const std::vector<std::string_view>& args) override
    {
        auto iss = std::istringstream{std::string(args.front())};
        T typedValue{};

        if (iss >> typedValue)
        {
            value = std::move(typedValue);
        }
        else
        {
            throw std::runtime_error("could not parse value: " + std::string(args.front()));
        }
    }

    void notify(const std::any& valueStore) const override
    {
        const T* value = std::any_cast<T>(&valueStore);
        if (typedPtr_ && value)
        {
            *typedPtr_ = *value;
        }
    }

    std::size_t minTokens() const override
    {
        return 1U;
    }

    std::size_t maxTokens() const override
    {
        return 1U;
    };

private:
    T* typedPtr_;
};

static constexpr std::string_view kSinglePrefix = "-";
static constexpr std::string_view kDoublePrefix = "--";

} // namespace detail

template <class T> std::shared_ptr<detail::TypedValue<T>> Value()
{
    return std::make_shared<detail::TypedValue<T>>(nullptr);
}

template <class T> std::shared_ptr<detail::TypedValue<T>> Value(T* v)
{
    return std::make_shared<detail::TypedValue<T>>(v);
}

class OptionParser;

class Option
{
    friend class OptionParser;

public:
    Option(std::string&& names, std::string&& description)
        : description_(std::move(description))
        , valueSemantic_(std::make_shared<detail::UntypedValue>())
        , isRequired_(false)
        , isUsed_(false)
    {
        setNames(names);
    }

    Option(std::string&& names,
           std::shared_ptr<detail::ValueSemantic> valueSemantic,
           std::string&& description)
        : description_(std::move(description))
        , valueSemantic_(valueSemantic)
        , isRequired_(false)
        , isUsed_(false)
    {
        setNames(names);
    }

    void setNames(const std::string& names)
    {
        auto end = names.find_first_of(',');
        if (end == std::string::npos)
        {
            baseName_ = names;
        }
        else
        {
            auto start = names.find_first_not_of(' ', end + 1);
            if (start == std::string::npos)
            {
                throw std::runtime_error("invalid option name");
            }
            baseName_ = names.substr(0, end);
            aliasName_ = names.substr(start);
        }
    }

    template <typename Iterator> void consume(Iterator start, Iterator end)
    {
        if (isUsed_)
        {
            throw std::runtime_error("duplicated option");
        }
        isUsed_ = true;

        std::size_t distance = std::distance(start, end);

        if (distance < valueSemantic_->minTokens())
        {
            throw std::runtime_error("not enough arguments");
        }

        if (distance > valueSemantic_->maxTokens())
        {
            throw std::runtime_error("too many arguments");
        }

        if (distance > 0)
        {
            std::vector<std::string_view> range{start, end};
            valueSemantic_->parse(value_, range);
        }
        else
        {
            valueSemantic_->parse(value_, {});
        }
    }

private:
    template <typename T> T get() const
    {
        if (!value_.has_value())
        {
            throw std::runtime_error("no value provided for '" + baseName_ +
                                     "'");
        }
        return std::any_cast<T>(value_);
    }

    template <typename T> std::optional<T> present() const
    {
        if (!value_.has_value())
        {
            return std::nullopt;
        }
        return std::any_cast<T>(value_);
    }

    void validate() const
    {
        if (!isUsed_ && isRequired_)
        {
            throw std::runtime_error("'" + baseName_ + "' must be specified");
        }
        if (isUsed_ && isRequired_ && !value_.has_value())
        {
            throw std::runtime_error("no value for '" + baseName_ + "' option");
        }
        if (valueSemantic_)
        {
            valueSemantic_->notify(value_);
        }
    }

private:
    std::string baseName_;
    std::optional<std::string> aliasName_;
    std::string description_;
    std::any value_;
    std::shared_ptr<detail::ValueSemantic> valueSemantic_;
    bool isRequired_;
    bool isUsed_;
};

class OptionParser
{
private:
    using OptionList = std::list<Option>;
    using OptionIterator = OptionList::iterator;

public:
    OptionParser() = default;
    ~OptionParser() = default;

    OptionParser(const OptionParser& other) = delete;
    OptionParser& operator=(const OptionParser& other) = delete;

    OptionParser(OptionParser&& other) = delete;
    OptionParser& operator=(OptionParser&& other) = delete;

    template <typename T>
    Option& add(std::string names, std::shared_ptr<detail::TypedValue<T>> value,
                std::string description)
    {
        auto it = options_.emplace(std::cend(options_), std::move(names), value,
                                   std::move(description));
        setOptions(it);
        return *it;
    }

    Option& add(std::string names, std::string description)
    {
        auto it = options_.emplace(std::cend(options_), std::move(names),
                                   std::move(description));
        setOptions(it);
        return *it;
    }

    static inline std::string_view trimDashes(std::string_view arg)
    {
        if (arg.size() > 2 && startsWith(arg, detail::kDoublePrefix))
            return arg.substr(2);
        if (arg.size() > 1 && startsWith(arg, detail::kSinglePrefix))
            return arg.substr(1);
        return arg;
    }

    static inline bool startsWith(std::string_view str, std::string_view prefix)
    {
        return str.rfind(prefix, 0) == 0;
    }

    void parse(int argc, char* argv[])
    {
        std::vector<std::string_view> args{(argc > 1 ? argv + 1 : argv),
                                           argv + argc};
        auto allocatedArgs = preprocess(args);
        postprocess(allocatedArgs);
    }

    void parse(const std::vector<std::string_view>& args)
    {
        auto allocatedArgs = preprocess(args);
        postprocess(allocatedArgs);
    }

    void parse(const std::vector<std::string>& args)
    {
        auto allocatedArgs = preprocess(args);
        postprocess(allocatedArgs);
    }

    template <typename T = std::string> T get(std::string_view name) const
    {
        if (!parsed_)
        {
            throw std::logic_error("attempt to get value before parsing");
        }
        return (*this)[name].get<T>();
    }

    template <typename T = std::string>
    std::optional<T> present(std::string_view name) const
    {
        return (*this)[name].present<T>();
    }

    bool isUsed(std::string_view name) const
    {
        return (*this)[name].isUsed_;
    }

    void help(std::ostream& os, std::string_view usageName = "") const
    {
        usage(os, usageName);

        os << "Allowed options:\n";

        for (auto option : options_)
        {
            std::stringstream ss;

            ss << "  " << detail::kDoublePrefix << option.baseName_;
            if (option.aliasName_.has_value())
            {
                ss << " [ " << detail::kSinglePrefix
                   << option.aliasName_.value() << " ]";
            }

            if (option.valueSemantic_->minTokens() > 0U)
            {
                ss << " arg";
            }

            auto optionInfo = ss.str();
            os << optionInfo;
            for (unsigned pad = 25 - static_cast<unsigned>(optionInfo.size());
                 pad > 0; --pad)
            {
                os.put(' ');
            }

            os << option.description_ << "\n";
        }
    }

private:
    inline void setOptions(const OptionIterator& it)
    {
        optionMap_.insert_or_assign(it->baseName_, it);
        if (it->aliasName_.has_value())
        {
            optionMap_.insert_or_assign(it->aliasName_.value(), it);
        }
    }

    Option& operator[](std::string_view name) const
    {
        auto it = optionMap_.find(name);
        if (it == optionMap_.end())
        {
            throw std::runtime_error("no such option: " + std::string(name));
        }
        return *(it->second);
    }

    template <typename T = std::string_view>
    std::vector<std::string> preprocess(const std::vector<T>& args)
    {
        std::vector<std::string> result;
        auto begin = std::begin(args);
        auto end = std::end(args);

        for (auto arg = begin; arg != end; arg = std::next(arg))
        {
            if (arg->size() > 2 && startsWith(*arg, detail::kDoublePrefix))
            {
                auto assignPosition = arg->find_first_of('=');
                if (assignPosition != std::string::npos)
                {
                    result.push_back(
                        std::string(arg->substr(0, assignPosition)));
                    result.push_back(
                        std::string(arg->substr(assignPosition + 1)));
                    continue;
                }
            }
            result.push_back(std::string(*arg));
        }
        return result;
    }

    void postprocess(const std::vector<std::string>& args)
    {
        auto end = std::end(args);
        for (auto arg = std::begin(args); arg != end;)
        {
            auto optionName = trimDashes(*arg);
            auto foundOption = optionMap_.find(optionName);
            if (foundOption != optionMap_.end())
            {
                auto nextOption =
                    std::find_if(std::next(arg), end, [](auto& x) {
                        return startsWith(x, "--") || startsWith(x, "-");
                    });
                foundOption->second->consume(std::next(arg), nextOption);
                arg = nextOption;
            }
            else
            {
                throw std::runtime_error("unknown option: " +
                                         std::string(optionName));
            }
        }

        for (auto& option : options_)
        {
            option.validate();
        }
        parsed_ = true;
    }

    void usage(std::ostream& os, std::string_view usageName) const
    {
        os << "Usage:\n";

        os << "  " << usageName;

        for (auto option : options_)
        {
            os << " ";

            if (!option.isRequired_)
            {
                os << "[ ";
            }

            os << detail::kDoublePrefix << option.baseName_;
            if (option.valueSemantic_->minTokens() > 0U)
            {
                os << " arg";
            }

            if (!option.isRequired_)
            {
                os << " ]";
            }
        }
        os << "\n\n";
    }

private:
    OptionList options_;
    std::map<std::string_view, OptionIterator> optionMap_;
    std::string programName_;
    bool parsed_{false};
};

} // namespace snet::opt
