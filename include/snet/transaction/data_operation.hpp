#pragma once

template <typename T>
class IDataOperation
{
public:
    virtual ~IDataOperation() = default;
    virtual void apply(T& data) = 0;
    virtual void rollback(T& data) = 0;
    virtual bool validate(const T& data) const = 0;
};