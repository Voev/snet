#pragma once
#include <map>
#include <memory>
#include <functional>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

#include <casket/nonstd/optional.hpp>
#include <casket/json/json.hpp>

namespace snet::pki
{

enum class CommandErrorCode
{
    None = 0,
    InvalidArguments,
    ParseError,
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

    CommandError(CommandErrorCode c = CommandErrorCode::None)
        : code(c)
    {
    }

    CommandError(CommandErrorCode c, std::string msg)
        : code(c)
        , message(std::move(msg))
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
        case CommandErrorCode::ParseError:
            return "Parse error";
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

inline CommandResult<std::string> error(CommandErrorCode code, const std::string& msg)
{
    return CommandResult<std::string>(CommandError(code, msg));
}

inline CommandResult<std::string> error(CommandErrorCode code, std::string&& msg)
{
    return CommandResult<std::string>(CommandError(code, std::move(msg)));
}

inline CommandResult<std::string> error(CommandErrorCode code, const char* msg)
{
    return CommandResult<std::string>(CommandError(code, std::string(msg)));
}

inline CommandResult<std::string> error(const std::string& msg)
{
    return CommandResult<std::string>(CommandError(CommandErrorCode::ExecutionFailed, msg));
}

class PKICommandDispatcher final
{
public:
    using Handler = std::function<CommandResult<std::string>(const casket::json::Value&)>;

    PKICommandDispatcher() = default;
    ~PKICommandDispatcher() = default;

    void registerCommand(std::string name, std::string description, Handler handler, std::shared_ptr<casket::json::Schema> schema)
    {
        Command cmd;
        cmd.description = std::move(description);
        cmd.handler = std::move(handler);
        cmd.schema = std::move(schema);
        commands_[std::move(name)] = std::move(cmd);
    }

    void registerCommand(std::string name, std::string description, Handler handler)
    {
        Command cmd;
        cmd.description = std::move(description);
        cmd.handler = std::move(handler);
        commands_[std::move(name)] = std::move(cmd);
    }

    CommandResult<std::string> execute(const std::string& name, const casket::json::Value& params)
    {
        // Check if params contain --help or help flag
        if (params.is<std::string>())
        {
            if (casket::equals(*params.get<std::string>(), "help"))
            {
                return success(getCommandHelp(name));
            }
        }

        auto it = commands_.find(name);
        if (it == commands_.end())
        {
            return error(CommandErrorCode::CommandNotFound, "Unknown command: " + name);
        }

        const auto& cmd = it->second;

        // Validate schema if present
        if (cmd.schema)
        {
            std::vector<std::string> errors;
            casket::json::Value mutableParams = params;
            if (!cmd.schema->validate(mutableParams, errors))
            {
                std::string errorMsg = "Validation failed: ";
                for (size_t i = 0; i < errors.size(); ++i)
                {
                    errorMsg += errors[i];
                    if (i < errors.size() - 1)
                        errorMsg += "; ";
                }
                return error(CommandErrorCode::InvalidArguments, errorMsg);
            }
        }

        return cmd.handler(params);
    }

    CommandResult<std::string> execute(const std::string& name, const std::string& jsonString)
    {
        try
        {
            casket::json::Value params = casket::json::parseDSL(jsonString);
            return execute(name, params);
        }
        catch (const std::exception& e)
        {
            return error(CommandErrorCode::ParseError, e.what());
        }
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
    std::string getCommandHelp(const std::string& name) const
    {
        auto it = commands_.find(name);
        if (it == commands_.end())
        {
            return "Unknown command: " + name;
        }

        const auto& cmd = it->second;

        std::stringstream ss;
        ss << "Command: " << name << "\n";
        ss << "Description: " << cmd.description << "\n\n";

        if (cmd.schema)
        {
            ss << cmd.schema->generateHelp();
        }
        else
        {
            ss << "No parameters required.\n";
        }

        return ss.str();
    }

    struct Command
    {
        std::string description;
        Handler handler;
        std::shared_ptr<casket::json::Schema> schema;
    };

    std::map<std::string, Command> commands_;
};

} // namespace snet::pki