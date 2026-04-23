#include "ha_client.h"

#include "desfire_client.h"

#include <sstream>

#if defined(PIDESFIRE_HAS_LIBCURL)
#include <curl/curl.h>
#endif

namespace
{
#if defined(PIDESFIRE_HAS_LIBCURL)
size_t writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    std::string* output = static_cast<std::string*>(userdata);
    output->append(ptr, size * nmemb);
    return size * nmemb;
}
#endif
} // namespace

HomeAssistantClient::HomeAssistantClient(const AppConfig& config)
    : baseUrl_(config.haUrl),
      token_(config.haToken),
      entityPrefix_(config.haTagEntityPrefix)
{
}

std::string HomeAssistantClient::registrationSummary(const std::string& cardUuidHex) const
{
    if (baseUrl_.empty())
    {
        return "Home Assistant URL is not configured yet; registration is pending for card " + cardUuidHex + ".";
    }

    return "Planned Home Assistant registration for card " + cardUuidHex + " via " + baseUrl_ + ".";
}

bool HomeAssistantClient::registerTag(const IdentityRecord& identity, const std::string& tagUidHex, std::string* responseSummary) const
{
    if (baseUrl_.empty() || token_.empty())
    {
        if (responseSummary != nullptr)
        {
            *responseSummary = "Home Assistant URL or token is not configured; skipped registration.";
        }
        return false;
    }

#if !defined(PIDESFIRE_HAS_LIBCURL)
    if (responseSummary != nullptr)
    {
        *responseSummary = "This build does not include libcurl; skipped Home Assistant registration.";
    }
    return false;
#else
    CURL* curl = curl_easy_init();
    if (curl == nullptr)
    {
        if (responseSummary != nullptr)
        {
            *responseSummary = "Unable to initialize libcurl for Home Assistant registration.";
        }
        return false;
    }

    const std::string entityId = entityPrefix_ + tagUidHex;
    const std::string uniqueId = "pidesfire_" + tagUidHex;
    const std::string url = baseUrl_ + "/api/states/" + entityId;

    std::ostringstream payload;
    payload << '{'
            << "\"state\":\"provisioned\","
            << "\"attributes\":{"
            << "\"card_uuid\":\"" << identity.cardUuidHex << "\","
            << "\"issue_counter\":" << identity.issueCounter << ','
            << "\"flags\":" << static_cast<int>(identity.flags) << ','
            << "\"tag_uid\":\"" << tagUidHex << "\","
            << "\"unique_id\":\"" << uniqueId << "\"}}";
    const std::string payloadBody = payload.str();

    std::string responseBody;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, ("Authorization: Bearer " + token_).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payloadBody.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payloadBody.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);

    const CURLcode result = curl_easy_perform(curl);
    long responseCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (result != CURLE_OK)
    {
        if (responseSummary != nullptr)
        {
            *responseSummary = std::string("Home Assistant registration failed: ") + curl_easy_strerror(result);
        }
        return false;
    }

    if (responseSummary != nullptr)
    {
        *responseSummary = "Home Assistant registration HTTP " + std::to_string(responseCode) + ": " + responseBody;
    }

    return responseCode >= 200 && responseCode < 300;
#endif
}

TagLookupResult HomeAssistantClient::lookupTag(const std::string& tagUidHex) const
{
    TagLookupResult result;

    if (baseUrl_.empty() || token_.empty())
    {
        result.summary = "Home Assistant URL or token is not configured; lookup skipped.";
        return result;
    }

#if !defined(PIDESFIRE_HAS_LIBCURL)
    result.summary = "This build does not include libcurl; lookup skipped.";
    return result;
#else
    CURL* curl = curl_easy_init();
    if (curl == nullptr)
    {
        result.summary = "Unable to initialize libcurl for Home Assistant lookup.";
        return result;
    }

    const std::string entityId = entityPrefix_ + tagUidHex;
    const std::string url = baseUrl_ + "/api/states/" + entityId;

    std::string responseBody;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, ("Authorization: Bearer " + token_).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);

    const CURLcode curlResult = curl_easy_perform(curl);
    long responseCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (curlResult != CURLE_OK)
    {
        result.summary = std::string("Home Assistant lookup failed: ") + curl_easy_strerror(curlResult);
        return result;
    }

    if (responseCode == 200)
    {
        result.found = true;
        // Minimal extraction of "state" field without a JSON library dependency.
        const std::string stateKey = "\"state\":\"";
        const std::size_t keyPos = responseBody.find(stateKey);
        if (keyPos != std::string::npos)
        {
            const std::size_t valueStart = keyPos + stateKey.size();
            const std::size_t valueEnd = responseBody.find('"', valueStart);
            if (valueEnd != std::string::npos)
            {
                result.state = responseBody.substr(valueStart, valueEnd - valueStart);
            }
        }
        result.summary = "Found in Home Assistant (entity: " + entityId + ", state: " + result.state + ").";
    }
    else if (responseCode == 404)
    {
        result.summary = "Not found in Home Assistant (entity: " + entityId + ").";
    }
    else
    {
        result.summary = "Home Assistant lookup returned HTTP " + std::to_string(responseCode) + ".";
    }

    return result;
#endif
}