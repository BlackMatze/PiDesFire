#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct IdentityRecord {
    std::string cardUuidHex;
    std::uint32_t issueCounter;
    std::uint8_t flags;
};

struct ProvisionedCard {
    std::string tagUidHex;
    IdentityRecord identity;
};

class DesfireClient {
public:
    bool canUseHardware() const;
    std::string capabilitySummary() const;
    IdentityRecord prepareIdentityRecord() const;
    std::vector<std::uint8_t> encodeIdentityRecord(const IdentityRecord& identity) const;
    IdentityRecord decodeIdentityRecord(const std::vector<std::uint8_t>& bytes) const;
    std::vector<std::string> provisionPlan(const IdentityRecord& identity) const;
    ProvisionedCard provisionCard(const IdentityRecord& identity, const std::string& appAidHex, const std::string& siteKeyHex, const std::string& deviceName) const;
};