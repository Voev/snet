#pragma once

#include <string_view>
#include <snet/crypto/pointers.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::crypto
{

class StoreLoader final : public casket::NonCopyable
{
public:
    StoreLoader(std::string_view uri, const UiMethod* meth, void* data);

    ~StoreLoader() = default;

    bool isError();

    bool finished();

    void expect(int type);

    StoreInfoPtr load(int type);

private:
    StoreCtxPtr ctx_;
};

} // namespace snet::crypto
