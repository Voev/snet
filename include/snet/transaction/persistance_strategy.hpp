#pragma once
#include <string>
#include <casket/nonstd/optional.hpp>

class IPersistenceStrategy
{
public:
    virtual ~IPersistenceStrategy() = default;
    virtual bool save(const std::string& data) = 0;
    virtual nonstd::optional<std::string> load() = 0;
    virtual bool createBackup() = 0;
    virtual bool restoreFromBackup() = 0;
};
