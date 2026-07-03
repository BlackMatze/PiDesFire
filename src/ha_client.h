#pragma once

#include "config.h"
#include "desfire_client.h"

#include <string>

struct TagLookupResult
{
    bool found = false;
    std::string state;
    std::string summary;
};

class HomeAssistantClient
{
  public:
    explicit HomeAssistantClient(const AppConfig& config);

    std::string registrationSummary(const std::string& cardUuidHex) const;
    bool registerTag(const IdentityRecord& identity, const std::string& tagUidHex, std::string* responseSummary) const;
    TagLookupResult lookupTag(const std::string& tagUidHex) const;

  private:
    std::string baseUrl_;
    std::string token_;
    std::string scannerDeviceId_;
};