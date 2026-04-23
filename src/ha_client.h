#pragma once

#include "config.h"
#include "desfire_client.h"

#include <string>

class HomeAssistantClient {
public:
    explicit HomeAssistantClient(const AppConfig& config);

    std::string registrationSummary(const std::string& cardUuidHex) const;
    bool registerTag(const IdentityRecord& identity, const std::string& tagUidHex, std::string* responseSummary) const;

private:
    std::string baseUrl_;
    std::string token_;
    std::string entityPrefix_;
};