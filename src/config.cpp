#include "config.h"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace {
std::string trim(const std::string& value) {
    std::size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start])) != 0) {
        ++start;
    }

    std::size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }

    return value.substr(start, end - start);
}
}

std::map<std::string, std::string> ConfigLoader::parseSimpleYaml(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("Unable to open config file: " + path);
    }

    std::map<std::string, std::string> values;
    std::string line;
    while (std::getline(input, line)) {
        const std::string stripped = trim(line);
        if (stripped.empty() || stripped[0] == '#') {
            continue;
        }

        const std::size_t separator = stripped.find(':');
        if (separator == std::string::npos) {
            continue;
        }

        const std::string key = trim(stripped.substr(0, separator));
        const std::string value = trim(stripped.substr(separator + 1));
        values[key] = value;
    }

    return values;
}

AppConfig ConfigLoader::loadFromFile(const std::string& path) {
    std::map<std::string, std::string> values = parseSimpleYaml(path);

    const std::filesystem::path basePath(path);
    const std::filesystem::path localPath = basePath.parent_path() / "config.local.yaml";
    if (std::filesystem::exists(localPath)) {
        const std::map<std::string, std::string> localValues = parseSimpleYaml(localPath.string());
        values.insert(localValues.begin(), localValues.end());
        for (const auto& entry : localValues) {
            values[entry.first] = entry.second;
        }
    }

    AppConfig config;
    config.siteName = values.count("site_name") != 0 ? values.at("site_name") : "home";
    config.appAid = values.count("app_aid") != 0 ? values.at("app_aid") : "D15F01";
    config.cardIdFormat = values.count("card_id_format") != 0 ? values.at("card_id_format") : "uuid16";
    config.nfcDevice = values.count("nfc_device") != 0 ? values.at("nfc_device") : "default";
    config.haUrl = values.count("ha_url") != 0 ? values.at("ha_url") : std::string();
    config.haToken = values.count("ha_token") != 0 ? values.at("ha_token") : std::string();
    config.haTagEntityPrefix = values.count("ha_tag_entity_prefix") != 0 ? values.at("ha_tag_entity_prefix") : "tag.pidesfire_";
    config.haTagScannerDeviceId = values.count("ha_tag_scanner_device_id") != 0 ? values.at("ha_tag_scanner_device_id") : std::string();
    config.siteKeyHex = values.count("site_key_hex") != 0 ? values.at("site_key_hex") : std::string();
    return config;
}