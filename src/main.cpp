#include "card_provisioner.h"
#include "config.h"
#include "desfire_client.h"

#include <chrono>
#include <exception>
#include <iostream>
#include <string>
#include <thread>

namespace
{
void printUsage()
{
    std::cout << "PiDesFire provisioner\n\n"
              << "Usage:\n"
              << "  pidesfire show-layout [config-path]\n"
              << "  pidesfire inspect [config-path]\n"
              << "  pidesfire provision-dry-run [config-path]\n"
              << "  pidesfire provision [config-path]\n"
              << "  pidesfire scan [config-path]\n";
}

std::string configPathFromArgs(int argc, char** argv)
{
    if (argc >= 3)
    {
        return argv[2];
    }

    return "config.yaml";
}
} // namespace

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printUsage();
        return 1;
    }

    try
    {
        const std::string command = argv[1];
        const std::string configPath = configPathFromArgs(argc, argv);
        const AppConfig config = ConfigLoader::loadFromFile(configPath);

        if (command == "show-layout")
        {
            DesfireClient desfireClient;
            std::cout << "App AID: " << config.appAid << "\n"
                      << "Card ID format: " << config.cardIdFormat << "\n"
                      << "Hardware status: " << desfireClient.capabilitySummary() << "\n";
            return 0;
        }

        if (command == "provision-dry-run")
        {
            CardProvisioner provisioner(config);
            const ProvisionResult result = provisioner.dryRunProvision();

            std::cout << "Prepared identity record\n"
                      << "  card_uuid: " << result.identity.cardUuidHex << "\n"
                      << "  issue_counter: " << result.identity.issueCounter << "\n"
                      << "  flags: " << static_cast<int>(result.identity.flags) << "\n\n"
                      << "Planned provisioning steps\n";

            for (const std::string& step : result.steps)
            {
                std::cout << "  - " << step << "\n";
            }

            std::cout << "\n"
                      << result.homeAssistantSummary << "\n";
            return 0;
        }

        if (command == "provision")
        {
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

        if (command == "inspect")
        {
            DesfireClient client;
            if (!client.canUseHardware())
            {
                std::cerr << "Error: inspect requires libnfc/libfreefare support.\n";
                return 1;
            }

            while (true)
            {
                std::cout << "\nWaiting for card... (Ctrl+C to exit)\n";
                while (!client.pollForAnyCard(config.nfcDevice))
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }

                try
                {
                    const CardInspectResult result = client.inspectCard(config.appAid, config.nfcDevice);
                    std::cout << "\nCard detected\n"
                              << "  type:      " << result.tagType << "\n"
                              << "  name:      " << result.tagFriendlyName << "\n"
                              << "  uid:       " << (result.tagUidHex.empty() ? "unavailable" : result.tagUidHex) << "\n";

                    for (const std::string& detail : result.details)
                    {
                        std::cout << "  " << detail << "\n";
                    }
                }
                catch (const std::exception& exception)
                {
                    std::cout << "Unable to inspect card: " << exception.what() << "\n";
                }

                std::cout << "\nRemove the card to inspect another one...\n";
                client.waitForAnyCardRemoval(config.nfcDevice);
            }
        }

        if (command == "scan")
        {
            DesfireClient poller;
            if (!poller.canUseHardware())
            {
                std::cerr << "Error: scan requires libnfc/libfreefare support.\n";
                return 1;
            }

            CardProvisioner provisioner(config);

            while (true)
            {
                std::cout << "\nWaiting for card... (Ctrl+C to exit)\n";
                while (!poller.pollForCard(config.nfcDevice))
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }

                CardStatus status;
                try
                {
                    status = provisioner.checkCard();
                }
                catch (const std::exception& e)
                {
                    std::cout << "Card disappeared before it could be read (" << e.what() << "). Retrying...\n";
                    continue;
                }

                std::cout << "\nCard detected\n"
                          << "  tag_uid:    " << status.tagUidHex << "\n";

                if (status.hasIdentity)
                {
                    std::cout << "  app:        present\n"
                              << "  card_uuid:  " << status.identity.cardUuidHex << "\n";
                }
                else
                {
                    std::cout << "  app:        not present (blank or foreign card)\n";
                }

                if (status.knownInHomeAssistant)
                {
                    std::cout << "  HA status:  registered (state: " << status.haState << ")\n";
                }
                else
                {
                    std::cout << "  HA status:  " << status.haSummary << "\n";
                }

                const std::string prompt = status.hasIdentity
                                               ? "Provision again? This will overwrite the card. [y/N]: "
                                               : "Provision this card? [y/N]: ";

                std::cout << prompt << std::flush;
                std::string answer;
                std::getline(std::cin, answer);

                if (answer != "y" && answer != "Y")
                {
                    std::cout << "Skipping. Exiting.\n";
                    return 0;
                }

                const ProvisionResult result = provisioner.provision(true);
                std::cout << "Provisioned\n"
                          << "  tag_uid:    " << result.tagUidHex << "\n"
                          << "  card_uuid:  " << result.identity.cardUuidHex << "\n"
                          << "  registered: " << (result.registeredInHomeAssistant ? "yes" : "no") << "\n"
                          << "  " << result.homeAssistantSummary << "\n";

                std::cout << "\nRemove the card to continue...\n";
                poller.waitForCardRemoval(config.nfcDevice);
            }
        }

        printUsage();
        return 1;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "Error: " << exception.what() << "\n";
        return 1;
    }
}