#pragma once
#include <tuple>
#include <cctype>
#include <casket/nonstd/optional.hpp>
#include <casket/nonstd/string_view.hpp>

namespace snet::pki_fetch
{

class UrlParser
{
public:
    struct Result
    {
        std::string host;
        std::string port;
        std::string path;
        bool isHttps{false};
    };

    static nonstd::optional<Result> parse(nonstd::string_view url)
    {
        nonstd::string_view scheme;
        size_t schemeEnd = url.find("://");
        if (schemeEnd == nonstd::string_view::npos)
        {
            return nonstd::nullopt;
        }

        bool isHttps = false;

        scheme = url.substr(0, schemeEnd);
        if (scheme == "http")
        {
            // OK
        }
        else if (scheme == "https")
        {
            isHttps = true;
        }
        else
        {
            return nonstd::nullopt;
        }

        nonstd::string_view rest = url.substr(schemeEnd + 3);

        size_t pathStart = rest.find('/');
        nonstd::string_view authority = rest;
        nonstd::string_view path = "/";

        if (pathStart != nonstd::string_view::npos)
        {
            authority = rest.substr(0, pathStart);
            path = rest.substr(pathStart);
        }

        nonstd::string_view host;
        nonstd::string_view port;

        if (!authority.empty() && authority[0] == '[')
        {
            size_t bracketEnd = authority.find(']');
            if (bracketEnd == nonstd::string_view::npos)
            {
                return nonstd::nullopt;
            }

            host = authority.substr(0, bracketEnd + 1);

            if (authority.size() > bracketEnd + 1)
            {
                if (authority[bracketEnd + 1] == ':')
                {
                    port = authority.substr(bracketEnd + 2);
                    if (port.empty())
                    {
                        return nonstd::nullopt;
                    }
                }
                else
                {
                    return nonstd::nullopt;
                }
            }
            else
            {
                port = isHttps ? "443" : "80";
            }
        }
        else
        {
            size_t portStart = authority.find(':');
            if (portStart == nonstd::string_view::npos)
            {
                host = authority;
                port = isHttps ? "443" : "80";
            }
            else
            {
                host = authority.substr(0, portStart);
                port = authority.substr(portStart + 1);

                if (host.empty() || port.empty())
                {
                    return nonstd::nullopt;
                }
            }
        }

        if (host.empty())
        {
            return nonstd::nullopt;
        }

        return Result{std::string(host.begin(), host.end()),
                      std::string(port.begin(), port.end()),
                      std::string(path.begin(), path.end()),
                      isHttps};
    }
};

} // namespace snet::pki_fetch