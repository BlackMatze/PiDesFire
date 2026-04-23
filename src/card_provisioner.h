#pragma once

#include "config.h"
#include "desfire_client.h"
#include "ha_client.h"

#include <string>
#include <vector>

struct ProvisionResult
{
    IdentityRecord identity;
    std::vector<std::string> steps;
    std::string homeAssistantSummary;
    std::string tagUidHex;
    bool wroteToCard;
    bool registeredInHomeAssistant;
};

struct CardStatus
{
    std::string tagUidHex;
    bool hasIdentity = false;
    IdentityRecord identity;
    bool knownInHomeAssistant = false;
    std::string haState;
    std::string haSummary;
};

class CardProvisioner
{
  public:
    explicit CardProvisioner(AppConfig config);

    ProvisionResult dryRunProvision() const;
    ProvisionResult provision(bool registerInHomeAssistant) const;
    CardStatus checkCard() const;

  private:
    AppConfig config_;
    DesfireClient desfireClient_;
};