#include "ha_client.h"

#include "desfire_client.h"

#include <sstream>

#if defined(PIDESFIRE_HAS_LIBCURL)
#include <curl/curl.h>
#endif

namespace {
#if defined(PIDESFIRE_HAS_LIBCURL)
size_t writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* output = static_cast<std::string*>(userdata);
    output->append(ptr, size * nmemb);
    return size * nmemb;
}
#endif
}

HomeAssistantClient::HomeAssistantClient(const AppConfig& config)
    : baseUrl_(config.haUrl),
      token_(config.haToken),
      entityPrefix_(config.haTagEntityPrefix) {
}

std::string HomeAssistantClient::registrationSummary(const std::string& cardUuidHex) const {
    if (baseUrl_.empty()) {
        return "Home Assistant URL is not configured yet; registration is pending for card " + cardUuidHex + ".";
    }

    return "Planned Home Assistant registration for card " + cardUuidHex + " via " + baseUrl_ + ".";
}

bool HomeAssistantClient::registerTag(const IdentityRecord& identity, const std::string& tagUidHex, std::string* responseSummary) const {
    if (baseUrl_.empty() || token_.empty()) {
        if (responseSummary != nullptr) {
            *responseSummary = "Home Assistant URL or token is not configured; skipped registration.";
        }
        return false;
    }

#if !defined(PIDESFIRE_HAS_LIBCURL)
    if (responseSummary != nullptr) {
        *responseSummary = "This build does not include libcurl; skipped Home Assistant registration.";
    }
    return false;
#else
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        if (responseSummary != nullptr) {
            *responseSummary = "Unable to initialize libcurl for Home Assistant registration.";
        }
        return false;
    }

    const std::string entityId = entityPrefix_ + identity.cardUuidHex;
    const std::string url = baseUrl_ + "/api/states/" + entityId;

    std::ostringstream payload;
        payload << '{'
            << "\"state\":\"provisioned\","
            << "\"attributes\":{"
            << "\"card_uuid\":\"" << identity.cardUuidHex << "\","
            << "\"issue_counter\":" << identity.issueCounter << ','
            << "\"flags\":" << static_cast<int>(identity.flags) << ','
            << "\"tag_uid\":\"" << tagUidHex << "\"}}";

    std::string responseBody;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, ("Authorization: Bearer " + token_).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.str().c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.str().size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);

    const CURLcode result = curl_easy_perform(curl);
    long responseCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (result != CURLE_OK) {
        if (responseSummary != nullptr) {
            *responseSummary = std::string("Home Assistant registration failed: ") + curl_easy_strerror(result);
        }
        return false;
    }

    if (responseSummary != nullptr) {
        *responseSummary = "Home Assistant registration HTTP " + std::to_string(responseCode) + ": " + responseBody;
    }

    return responseCode >= 200 && responseCode < 300;
#endif
}