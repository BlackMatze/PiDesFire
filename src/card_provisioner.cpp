#include "card_provisioner.h"

CardProvisioner::CardProvisioner(AppConfig config)
    : config_(std::move(config)) {
}

ProvisionResult CardProvisioner::dryRunProvision() const {
    const IdentityRecord identity = desfireClient_.prepareIdentityRecord();
    HomeAssistantClient haClient(config_);

    ProvisionResult result;
    result.identity = identity;
    result.steps = desfireClient_.provisionPlan(identity);
    result.homeAssistantSummary = haClient.registrationSummary(identity.cardUuidHex);
    result.wroteToCard = false;
    result.registeredInHomeAssistant = false;
    return result;
}

ProvisionResult CardProvisioner::provision(bool registerInHomeAssistant) const {
    const IdentityRecord identity = desfireClient_.prepareIdentityRecord();
    const ProvisionedCard provisioned = desfireClient_.provisionCard(identity, config_.appAid, config_.siteKeyHex, config_.nfcDevice);
    HomeAssistantClient haClient(config_);

    ProvisionResult result;
    result.identity = provisioned.identity;
    result.steps = desfireClient_.provisionPlan(provisioned.identity);
    result.tagUidHex = provisioned.tagUidHex;
    result.wroteToCard = true;
    result.registeredInHomeAssistant = false;

    if (registerInHomeAssistant) {
        result.registeredInHomeAssistant = haClient.registerTag(provisioned.identity, provisioned.tagUidHex, &result.homeAssistantSummary);
    } else {
        result.homeAssistantSummary = haClient.registrationSummary(provisioned.identity.cardUuidHex);
    }

    return result;
}