
#pragma once

class ILockStrategy
{
public:
    virtual ~ILockStrategy() = default;
    virtual bool acquireRead() = 0;
    virtual bool acquireWrite() = 0;
    virtual void release() = 0;
    virtual bool isLocked() const = 0;
};

