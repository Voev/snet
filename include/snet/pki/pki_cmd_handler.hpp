#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <casket/dsl/dsl.hpp>

namespace snet::pki {

class CommandHandler {
public:
    virtual ~CommandHandler() = default;
    
    // ===== TO BE IMPLEMENTED BY DERIVED =====
    virtual Schema buildSchema() const = 0;
    virtual std::string execute(const std::shared_ptr<Object>& params) const = 0;
    virtual std::string getCommandName() const = 0;
    virtual std::string getDescription() const = 0;
    
    // ===== THREAD-SAFE SCHEMA ACCESS =====
    const Schema& getSchema() const {
        std::call_once(schemaInitFlag_, [this]() {
            cachedSchema_ = buildSchema();
        });
        return cachedSchema_;
    }
    
    // ===== MAIN HANDLER =====
    std::string handle(const std::string& dslInput) const {
        // 1. Parse
        Value parsed = parseDSL(dslInput);
        
        if (!std::holds_alternative<std::shared_ptr<Object>>(parsed)) {
            throw std::runtime_error("Expected object at root level");
        }
        auto root = std::get<std::shared_ptr<Object>>(parsed);
        
        // 2. Validate
        const Schema& schema = getSchema();
        std::vector<std::string> errors;
        if (!schema.validate(root, errors)) {
            std::string errorMsg = "Validation failed:\n";
            for (const auto& err : errors) {
                errorMsg += "  ✗ " + err + "\n";
            }
            throw std::runtime_error(errorMsg);
        }
        
        // 3. Execute business logic
        return execute(root);
    }
    
    // ===== HELP =====
    std::string getHelp() const {
        std::stringstream ss;
        ss << "Usage: " << getCommandName() << " [PARAMETERS]\n";
        ss << getDescription() << "\n\n";
        ss << getSchema().generateHelp();
        return ss.str();
    }
    
private:
    mutable Schema cachedSchema_;
    mutable std::once_flag schemaInitFlag_;
};


} // namespace snet::pki