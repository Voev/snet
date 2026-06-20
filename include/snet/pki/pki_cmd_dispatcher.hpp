#pragma once
#include <map>
#include <memory>
#include <functional>
#include <vector>
#include <string>
#include <unordered_map>
#include <snet/cmd/command.hpp>

namespace snet::pki
{

enum class CommandErrorCode{
    None = 0,
    InvalidArguments,
    CommandNotFound,
    ExecutionFailed,
    PolicyNotFound,
    PolicyAlreadyExists,
    KeyGenerationFailed,
    CertificateError,
    InternalError,
    PermissionDenied,
    InvalidState
};

struct CommandError
{
    CommandErrorCode code;
    std::string message;

    CommandError()
        : code(CommandErrorCode::None)
    {
    }
    CommandError(CommandErrorCode c, const std::string& msg = "")
        : code(c)
        , message(msg)
    {
    }

    bool isNone() const
    {
        return code == CommandErrorCode::None;
    }
    explicit operator bool() const
    {
        return code != CommandErrorCode::None;
    }

    std::string toString() const
    {
        if (message.empty())
        {
            return codeToString();
        }
        return codeToString() + ": " + message;
    }

    std::string codeToString() const
    {
        switch (code)
        {
        case CommandErrorCode::None:
            return "Success";
        case CommandErrorCode::InvalidArguments:
            return "Invalid arguments";
        case CommandErrorCode::CommandNotFound:
            return "Command not found";
        case CommandErrorCode::ExecutionFailed:
            return "Execution failed";
        case CommandErrorCode::PolicyNotFound:
            return "Policy not found";
        case CommandErrorCode::PolicyAlreadyExists:
            return "Policy already exists";
        case CommandErrorCode::KeyGenerationFailed:
            return "Key generation failed";
        case CommandErrorCode::CertificateError:
            return "Certificate error";
        case CommandErrorCode::InternalError:
            return "Internal error";
        case CommandErrorCode::PermissionDenied:
            return "Permission denied";
        case CommandErrorCode::InvalidState:
            return "Invalid state";
        default:
            return "Unknown error";
        }
    }
};

template <typename T>
using CommandResult = casket::Result<T, CommandError>;

template <typename T>
inline CommandResult<T> success(T&& value)
{
    return CommandResult<T>(std::forward<T>(value));
}

template <typename T>
inline CommandResult<T> success(const T& value)
{
    return CommandResult<T>(value);
}

inline CommandResult<std::string> success()
{
    return CommandResult<std::string>("OK");
}

template <typename T>
inline CommandResult<T> error(CommandErrorCode code, const std::string& msg = "")
{
    return CommandResult<T>(CommandError(code, msg));
}

inline CommandResult<std::string> error(const std::string& msg)
{
    return CommandResult<std::string>(CommandError(CommandErrorCode::ExecutionFailed, msg));
}

class PKICommandDispatcher final
{
public:
    using Handler = std::function<CommandResult<std::string>(const std::vector<std::string>&)>;

    PKICommandDispatcher() = default;
    ~PKICommandDispatcher() = default;

    void registerCommand(const std::string& name, const std::string& description, Handler handler)
    {
        commands_[name] = {description, std::move(handler)};
    }

    CommandResult<std::string> execute(const std::string& name, const std::vector<std::string>& args) const
    {
        auto it = commands_.find(name);
        if (it == commands_.end())
        {
            return CommandResult<std::string>("Unknown command: " + name);
        }
        return it->second.handler(args);
    }

    void printCommands(std::ostream& os) const
    {
        os << "Available commands:\n";
        for (const auto& [name, cmd] : commands_)
        {
            os << "  " << std::left << std::setw(20) << name << cmd.description << "\n";
        }
    }

    bool hasCommand(const std::string& name) const
    {
        return commands_.find(name) != commands_.end();
    }

    std::vector<std::string> getCommandNames() const
    {
        std::vector<std::string> names;
        names.reserve(commands_.size());
        for (const auto& [name, _] : commands_)
        {
            names.push_back(name);
        }
        return names;
    }

private:
    struct Command
    {
        std::string description;
        Handler handler;
    };

    std::unordered_map<std::string, Command> commands_;
};

} // namespace snet::pki