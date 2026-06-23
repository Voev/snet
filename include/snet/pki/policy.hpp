#pragma once
#include <cstdint>
#include <string>

#include <casket/nonstd/string_view.hpp>
#include <casket/utils/exception.hpp>
#include <snet/utils/file_db.hpp>

namespace snet::pki
{

enum class PolicyStatus : uint32_t
{
    CREATED = 0,   // Policy created, no components added yet
    KEY_ADDED = 1, // Private key added
    COMPLETE = 2,  // Both key and certificate present
    ENABLED = 3,   // Policy is active and ready to use
    DISABLED = 4,  // Policy disabled by administrator
    NOT_VALID = 5  // Certificate expired or invalid
};

struct Policy
{
    std::string name;
    std::string caCertPath;
    std::string caKeyPath;
    PolicyStatus status;

    Policy()
        : status(PolicyStatus::CREATED)
    {
    }

    Policy(const std::string& n)
        : name(n)
        , status(PolicyStatus::CREATED)
    {
    }

    bool hasKey() const
    {
        return !caKeyPath.empty();
    }

    bool hasCertificate() const
    {
        return !caCertPath.empty();
    }

    bool isComplete() const
    {
        return hasKey() && hasCertificate();
    }

    bool isExpired() const
    {
        return status == PolicyStatus::NOT_VALID;
    }

    bool isReady() const
    {
        return status == PolicyStatus::ENABLED && isComplete();
    }

    bool canSign() const
    {
        return isReady();
    }

    // Update status based on current components
    void updateStatus()
    {
        // Do not auto-update DISABLED or NOT_VALID
        if (status == PolicyStatus::DISABLED || status == PolicyStatus::NOT_VALID)
        {
            return;
        }

        bool hasKey = !caKeyPath.empty();
        bool hasCert = !caCertPath.empty();

        if (hasKey && hasCert)
        {
            // Keep ENABLED if already set, otherwise go to COMPLETE
            if (status != PolicyStatus::ENABLED)
            {
                status = PolicyStatus::COMPLETE;
            }
        }
        else if (hasKey)
        {
            status = PolicyStatus::KEY_ADDED;
        }
        else
        {
            // No key -> always CREATED (cert without key is meaningless)
            status = PolicyStatus::CREATED;
        }
    }

    // Add private key to policy
    void addKey(const std::string& keyPath)
    {
        casket::ThrowIfTrue(!caKeyPath.empty(), "key already set");
        casket::ThrowIfTrue(status == PolicyStatus::ENABLED, "cannot add key to enabled policy");
        casket::ThrowIfTrue(status == PolicyStatus::DISABLED, "cannot add key to disabled policy");
        casket::ThrowIfTrue(status == PolicyStatus::NOT_VALID, "cannot add key to not valid policy");

        caKeyPath = keyPath;
        updateStatus(); // Becomes KEY_ADDED or COMPLETE (if cert exists)
    }

    // Add certificate to policy (requires key to be present)
    void addCertificate(const std::string& certPath)
    {
        casket::ThrowIfTrue(!caCertPath.empty(), "certificate already set");
        casket::ThrowIfTrue(status == PolicyStatus::ENABLED, "cannot add certificate to enabled policy");
        casket::ThrowIfTrue(status == PolicyStatus::DISABLED, "cannot add certificate to disabled policy");
        casket::ThrowIfTrue(status == PolicyStatus::NOT_VALID, "cannot add certificate to not valid policy");
        casket::ThrowIfTrue(!hasKey(), "cannot add certificate: key must be added first");

        caCertPath = certPath;
        // Now both key and cert present -> COMPLETE
        status = PolicyStatus::COMPLETE;
    }

    // Enable policy for use
    void enable()
    {
        casket::ThrowIfTrue(status != PolicyStatus::COMPLETE, "cannot enable: policy must be COMPLETE");
        casket::ThrowIfTrue(!isComplete(), "cannot enable: policy must have both key and certificate");
        status = PolicyStatus::ENABLED;
    }

    // Disable policy
    void disable()
    {
        casket::ThrowIfTrue(status != PolicyStatus::ENABLED && status != PolicyStatus::COMPLETE,
                            "cannot disable: policy must be ENABLED or COMPLETE");
        status = PolicyStatus::DISABLED;
    }

    // Mark policy as invalid (e.g., certificate expired)
    void markNotValid()
    {
        casket::ThrowIfTrue(status != PolicyStatus::ENABLED, "cannot mark not valid: policy must be ENABLED");
        status = PolicyStatus::NOT_VALID;
    }

    // Restore policy from DISABLED or NOT_VALID state
    void restore()
    {
        casket::ThrowIfTrue(status != PolicyStatus::DISABLED && status != PolicyStatus::NOT_VALID,
                            "cannot restore: policy must be DISABLED or NOT_VALID");

        // Restore based on available components
        if (isComplete())
        {
            status = PolicyStatus::COMPLETE;
        }
        else if (hasKey())
        {
            status = PolicyStatus::KEY_ADDED;
        }
        else
        {
            status = PolicyStatus::CREATED;
        }
    }

    // Convert to database row
    Row toRow() const
    {
        Row row(4);
        row[0] = makeFieldValue(name);
        row[1] = makeFieldValue(caCertPath);
        row[2] = makeFieldValue(caKeyPath);
        row[3] = makeFieldValue(static_cast<std::uint32_t>(status));
        return row;
    }

    // Create from database row
    static Policy fromRow(const Row& row)
    {
        Policy policy;
        if (row.size() >= 4)
        {
            policy.name = getFieldValue<std::string>(row[0]);
            policy.caCertPath = getFieldValue<std::string>(row[1]);
            policy.caKeyPath = getFieldValue<std::string>(row[2]);
            policy.status = static_cast<PolicyStatus>(getFieldValue<std::uint32_t>(row[3]));
        }
        return policy;
    }

    static nonstd::string_view statusToString(PolicyStatus status)
    {
        switch (status)
        {
        case PolicyStatus::CREATED:
            return "CREATED - policy created, no components added";
        case PolicyStatus::KEY_ADDED:
            return "KEY_ADDED - private key added";
        case PolicyStatus::COMPLETE:
            return "COMPLETE - both key and certificate present";
        case PolicyStatus::ENABLED:
            return "ENABLED - policy is active and ready to use";
        case PolicyStatus::DISABLED:
            return "DISABLED - policy disabled, can not be used for signing";
        case PolicyStatus::NOT_VALID:
            return "NOT_VALID - certificate expired or invalid";
        default:
            return "UNKNOWN";
        }
    }

    void print(std::ostream& os) const
    {
        os << "Policy: " << name << "\n";
        os << "  Status: " << statusToString(status) << "\n";
        os << "  CA Certificate: " << (caCertPath.empty() ? "not set" : caCertPath) << "\n";
        os << "  CA Key: " << (caKeyPath.empty() ? "not set" : caKeyPath) << "\n";
    }
};

} // namespace snet::pki