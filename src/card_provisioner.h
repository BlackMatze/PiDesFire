#pragma once

#include "config.h"
#include "desfire_client.h"
#include "ha_client.h"

#include <string>
#include <vector>

struct ProvisionResult {
    IdentityRecord identity;
    std::vector<std::string> steps;
    std::string homeAssistantSummary;
    std::string tagUidHex;
    bool wroteToCard;
    bool registeredInHomeAssistant;
};

class CardProvisioner {
public:
    explicit CardProvisioner(AppConfig config);

    ProvisionResult dryRunProvision() const;
    ProvisionResult provision(bool registerInHomeAssistant) const;

private:
    AppConfig config_;
    DesfireClient desfireClient_;
};