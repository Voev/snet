#pragma once
#include <map>
#include <string>
#include <vector>
#include <casket/utils/singleton.hpp>

class ConfigParser : public casket::utils::Singleton<ConfigParser>
{
public:
    using Section = std::map<std::string, std::string>;
    using Sections = std::map<std::string, Section>;

public:
    void parse(const std::string& filename);
    Sections getSections() const;
    Section getSectionBody(const std::string& section) const;

private:
    Sections sections_;
};