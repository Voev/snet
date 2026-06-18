#pragma once

#include <shared_mutex>

#include <deque>
#include <fstream>
#include <filesystem>

#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <snet/transaction/transaction.hpp>


class FileLockStrategy : public ILockStrategy
{
public:
    explicit FileLockStrategy(const std::string& lockFilePath)
        : lockFilePath_(lockFilePath)
        , fd_(-1)
    {
    }

    ~FileLockStrategy() override
    {
        release();
    }

    bool acquireRead() override
    {
        return acquireLock(LOCK_SH);
    }

    bool acquireWrite() override
    {
        return acquireLock(LOCK_EX);
    }

    void release() override
    {
        if (fd_ != -1)
        {
            flock(fd_, LOCK_UN);
            close(fd_);
            fd_ = -1;
        }
    }

    bool isLocked() const override
    {
        return fd_ != -1;
    }

private:
    bool acquireLock(int lockType)
    {
        if (fd_ != -1)
        {
            release();
        }

        fd_ = open(lockFilePath_.c_str(), O_RDWR | O_CREAT, 0666);
        if (fd_ == -1)
        {
            return false;
        }

        if (flock(fd_, lockType) == -1)
        {
            close(fd_);
            fd_ = -1;
            return false;
        }

        return true;
    }

    std::string lockFilePath_;
    int fd_;
};

// ============================================
// Сохранение в файловую систему
// ============================================
class FileSystemPersistence : public IPersistenceStrategy
{
public:
    explicit FileSystemPersistence(const std::string& filePath, bool useAtomicWrite = true)
        : filePath_(filePath)
        , useAtomicWrite_(useAtomicWrite)
    {
    }

    bool save(const std::string& data) override
    {
        if (useAtomicWrite_)
        {
            return atomicSave(data);
        }
        return directSave(data);
    }

    std::optional<std::string> load() override
    {
        if (!std::filesystem::exists(filePath_))
        {
            return std::nullopt;
        }

        std::ifstream file(filePath_, std::ios::binary);
        if (!file.is_open())
        {
            return std::nullopt;
        }

        std::ostringstream oss;
        oss << file.rdbuf();
        return oss.str();
    }

    bool createBackup() override
    {
        auto backupPath =
            filePath_ + ".backup." + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());

        try
        {
            std::filesystem::copy_file(filePath_, backupPath, std::filesystem::copy_options::overwrite_existing);
            backupFiles_.push_back(backupPath);

            // Удаляем старые бэкапы если их слишком много
            while (backupFiles_.size() > maxBackups_)
            {
                std::filesystem::remove(backupFiles_.front());
                backupFiles_.pop_front();
            }

            return true;
        }
        catch (const std::filesystem::filesystem_error&)
        {
            return false;
        }
    }

    bool restoreFromBackup() override
    {
        if (backupFiles_.empty())
        {
            return false;
        }

        try
        {
            std::filesystem::copy_file(backupFiles_.back(), filePath_,
                                       std::filesystem::copy_options::overwrite_existing);
            return true;
        }
        catch (const std::filesystem::filesystem_error&)
        {
            return false;
        }
    }

    void setMaxBackups(size_t max)
    {
        maxBackups_ = max;
    }
    size_t getBackupCount() const
    {
        return backupFiles_.size();
    }

private:
    bool atomicSave(const std::string& data)
    {
        auto tmpPath = filePath_ + ".tmp." + std::to_string(getpid()) + "." +
                       std::to_string(std::chrono::system_clock::now().time_since_epoch().count());

        // Пишем во временный файл
        {
            std::ofstream tmp(tmpPath, std::ios::binary | std::ios::trunc);
            if (!tmp.is_open())
            {
                return false;
            }

            tmp << data;
            tmp.flush();

            if (tmp.fail())
            {
                std::filesystem::remove(tmpPath);
                return false;
            }
        }

        // Атомарно заменяем основной файл
        try
        {
            std::filesystem::rename(tmpPath, filePath_);
            return true;
        }
        catch (const std::filesystem::filesystem_error&)
        {
            std::filesystem::remove(tmpPath);
            return false;
        }
    }

    bool directSave(const std::string& data)
    {
        std::ofstream file(filePath_, std::ios::binary | std::ios::trunc);
        if (!file.is_open())
        {
            return false;
        }

        file << data;
        return !file.fail();
    }

    std::string filePath_;
    bool useAtomicWrite_;
    size_t maxBackups_{5};
    std::deque<std::string> backupFiles_;
};
