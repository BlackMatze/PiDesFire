#include "card_provisioner.h"
#include "config.h"
#include "desfire_client.h"

#include <exception>
#include <iostream>
#include <string>

namespace {
void printUsage() {
    std::cout << "PiDesFire provisioner\n\n"
              << "Usage:\n"
              << "  pidesfire show-layout [config-path]\n"
              << "  pidesfire provision-dry-run [config-path]\n"
              << "  pidesfire provision [config-path]\n";
}

std::string configPathFromArgs(int argc, char** argv) {
    if (argc >= 3) {
        return argv[2];
    }

    return "config.yaml";
}
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    try {
        const std::string command = argv[1];
        const std::string configPath = configPathFromArgs(argc, argv);
        const AppConfig config = ConfigLoader::loadFromFile(configPath);

        if (command == "show-layout") {
            DesfireClient desfireClient;
            std::cout << "App AID: " << config.appAid << "\n"
                      << "Card ID format: " << config.cardIdFormat << "\n"
                      << "Hardware status: " << desfireClient.capabilitySummary() << "\n";
            return 0;
        }

        if (command == "provision-dry-run") {
            CardProvisioner provisioner(config);
            const ProvisionResult result = provisioner.dryRunProvision();

            std::cout << "Prepared identity record\n"
                      << "  card_uuid: " << result.identity.cardUuidHex << "\n"
                      << "  issue_counter: " << result.identity.issueCounter << "\n"
                      << "  flags: " << static_cast<int>(result.identity.flags) << "\n\n"
                      << "Planned provisioning steps\n";

            for (const std::string& step : result.steps) {
                std::cout << "  - " << step << "\n";
            }

            std::cout << "\n" << result.homeAssistantSummary << "\n";
            return 0;
        }

        if (command == "provision") {
            CardProvisioner provisioner(config);
            const ProvisionResult result = provisioner.provision(true);

            std::cout << "Provisioned card\n"
                      << "  tag_uid: " << result.tagUidHex << "\n"
                      << "  card_uuid: " << result.identity.cardUuidHex << "\n"
                      << "  issue_counter: " << result.identity.issueCounter << "\n"
                      << "  flags: " << static_cast<int>(result.identity.flags) << "\n"
                      << "  wrote_to_card: " << (result.wroteToCard ? "yes" : "no") << "\n"
                      << "  registered_in_home_assistant: " << (result.registeredInHomeAssistant ? "yes" : "no") << "\n\n"
                      << result.homeAssistantSummary << "\n";
            return result.registeredInHomeAssistant ? 0 : 2;
        }

        printUsage();
        return 1;
    } catch (const std::exception& exception) {
        std::cerr << "Error: " << exception.what() << "\n";
        return 1;
    }
}