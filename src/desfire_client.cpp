#include "desfire_client.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <stdexcept>
#include <random>
#include <sstream>

#if defined(PIDESFIRE_HAS_OPENSSL)
#include <openssl/sha.h>
#endif

#if defined(PIDESFIRE_HAS_LIBNFC)
#include <nfc/nfc.h>
#endif

#if defined(PIDESFIRE_HAS_LIBFREEFARE)
#include <freefare.h>
#endif

namespace {
constexpr std::size_t kIdentityRecordSize = 32;
constexpr uint8_t kFormatVersion = 0x01;
constexpr uint8_t kIdentityFileNumber = 0x01;
constexpr uint8_t kMetadataFileNumber = 0x02;
constexpr uint32_t kMetadataFileSize = 32;
constexpr uint8_t kApplicationKeyCount = 3;

std::vector<std::uint8_t> hexToBytes(const std::string& hex) {
    if ((hex.size() % 2) != 0) {
        throw std::runtime_error("Hex value must have an even number of characters.");
    }

    std::vector<std::uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (std::size_t index = 0; index < hex.size(); index += 2) {
        const std::string byteString = hex.substr(index, 2);
        bytes.push_back(static_cast<std::uint8_t>(std::stoul(byteString, nullptr, 16)));
    }

    return bytes;
}

std::string bytesToHex(const std::uint8_t* data, std::size_t size) {
    std::ostringstream output;
    for (std::size_t index = 0; index < size; ++index) {
        output << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[index]);
    }
    return output.str();
}

std::array<std::uint8_t, 16> deriveAesKey(const std::string& siteKeyHex, const std::string& appAidHex, const std::string& tagUidHex, const std::string& cardUuidHex, std::uint8_t keySlot) {
    const std::string material = siteKeyHex + ":" + appAidHex + ":" + tagUidHex + ":" + cardUuidHex + ":" + std::to_string(static_cast<int>(keySlot));

#if defined(PIDESFIRE_HAS_OPENSSL)
    std::array<std::uint8_t, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char*>(material.data()), material.size(), digest.data());

    std::array<std::uint8_t, 16> keyBytes{};
    std::copy_n(digest.begin(), keyBytes.size(), keyBytes.begin());
    return keyBytes;
#else
    std::array<std::uint8_t, 16> keyBytes{};
    for (std::size_t index = 0; index < keyBytes.size(); ++index) {
        keyBytes[index] = static_cast<std::uint8_t>((material[index % material.size()] + index) & 0xFF);
    }
    return keyBytes;
#endif
}

#if defined(PIDESFIRE_HAS_LIBNFC) && defined(PIDESFIRE_HAS_LIBFREEFARE)
class NfcContext {
public:
    NfcContext() {
        nfc_init(&context_);
        if (context_ == nullptr) {
            throw std::runtime_error("Failed to initialize libnfc context.");
        }
    }

    ~NfcContext() {
        if (context_ != nullptr) {
            nfc_exit(context_);
        }
    }

    nfc_context* get() const {
        return context_;
    }

private:
    nfc_context* context_ = nullptr;
};

class TagSession {
public:
    TagSession(nfc_device* device, MifareTag tag)
        : device_(device), tag_(tag) {
    }

    ~TagSession() {
        if (tag_ != nullptr) {
            mifare_desfire_disconnect(tag_);
        }
        if (device_ != nullptr) {
            nfc_close(device_);
        }
    }

    MifareTag tag() const {
        return tag_;
    }

private:
    nfc_device* device_;
    MifareTag tag_;
};

TagSession openDesfireTag(nfc_context* context, const std::string& deviceName) {
    const char* requestedDevice = deviceName == "default" ? nullptr : deviceName.c_str();
    nfc_device* device = nfc_open(context, requestedDevice);
    if (device == nullptr) {
        throw std::runtime_error("Unable to open NFC device.");
    }

    MifareTag* tags = freefare_get_tags(device);
    if (tags == nullptr) {
        nfc_close(device);
        throw std::runtime_error("Unable to enumerate NFC tags.");
    }

    MifareTag desfireTag = nullptr;
    for (std::size_t index = 0; tags[index] != nullptr; ++index) {
        if (freefare_get_tag_type(tags[index]) == DESFIRE) {
            desfireTag = tags[index];
            break;
        }
    }

    if (desfireTag == nullptr) {
        freefare_free_tags(tags);
        nfc_close(device);
        throw std::runtime_error("No DESFire card present on the reader.");
    }

    if (mifare_desfire_connect(desfireTag) < 0) {
        const std::string error = freefare_strerror(desfireTag);
        freefare_free_tags(tags);
        nfc_close(device);
        throw std::runtime_error("Unable to connect to DESFire card: " + error);
    }

    return TagSession(device, desfireTag);
}

MifareDESFireAID aidFromHex(const std::string& appAidHex) {
    return mifare_desfire_aid_new(static_cast<uint32_t>(std::stoul(appAidHex, nullptr, 16)));
}

void ensureDefaultPiccAuth(MifareTag tag) {
    std::array<uint8_t, 16> zeroKey{};
    MifareDESFireKey defaultKey = mifare_desfire_aes_key_new(zeroKey.data());
    if (defaultKey == nullptr) {
        throw std::runtime_error("Unable to allocate default PICC key.");
    }

    const int authResult = mifare_desfire_authenticate_aes(tag, 0, defaultKey);
    mifare_desfire_key_free(defaultKey);
    if (authResult < 0) {
        throw std::runtime_error("PICC authentication with the default key failed.");
    }
}

bool applicationExists(MifareTag tag, const std::string& appAidHex) {
    MifareDESFireAID* aids = nullptr;
    size_t count = 0;
    if (mifare_desfire_get_application_ids(tag, &aids, &count) < 0) {
        throw std::runtime_error("Unable to enumerate DESFire applications.");
    }

    const uint32_t desiredAid = static_cast<uint32_t>(std::stoul(appAidHex, nullptr, 16));
    bool found = false;
    for (size_t index = 0; index < count; ++index) {
        if (mifare_desfire_aid_get_aid(aids[index]) == desiredAid) {
            found = true;
            break;
        }
    }
    mifare_desfire_free_application_ids(aids);
    return found;
}

void ensureApplication(MifareTag tag, const std::string& appAidHex) {
    if (applicationExists(tag, appAidHex)) {
        return;
    }

    MifareDESFireAID aid = aidFromHex(appAidHex);
    if (aid == nullptr) {
        throw std::runtime_error("Unable to allocate DESFire AID.");
    }

    const uint8_t keySettings = 0x0F;
    const uint8_t keyCount = static_cast<uint8_t>(APPLICATION_CRYPTO_AES | kApplicationKeyCount);
    if (mifare_desfire_create_application_aes(tag, aid, keySettings, keyCount) < 0) {
        throw std::runtime_error("Unable to create DESFire application.");
    }
}

void selectApplication(MifareTag tag, const std::string& appAidHex) {
    MifareDESFireAID aid = aidFromHex(appAidHex);
    if (aid == nullptr) {
        throw std::runtime_error("Unable to allocate DESFire AID.");
    }
    if (mifare_desfire_select_application(tag, aid) < 0) {
        throw std::runtime_error("Unable to select DESFire application.");
    }
}

void configureKeys(MifareTag tag, const std::string& siteKeyHex, const std::string& appAidHex, const std::string& tagUidHex, const std::string& cardUuidHex) {
    std::array<uint8_t, 16> zeroKey{};
    MifareDESFireKey oldMaster = mifare_desfire_aes_key_new(zeroKey.data());
    if (oldMaster == nullptr) {
        throw std::runtime_error("Unable to allocate old app master key.");
    }

    for (uint8_t keyNo = 0; keyNo < kApplicationKeyCount; ++keyNo) {
        const std::array<std::uint8_t, 16> material = deriveAesKey(siteKeyHex, appAidHex, tagUidHex, cardUuidHex, keyNo);
        MifareDESFireKey newKey = mifare_desfire_aes_key_new(const_cast<uint8_t*>(material.data()));
        if (newKey == nullptr) {
            mifare_desfire_key_free(oldMaster);
            throw std::runtime_error("Unable to allocate diversified AES key.");
        }

        const MifareDESFireKey oldKeyForChange = (keyNo == 0) ? oldMaster : nullptr;
        if (mifare_desfire_change_key(tag, keyNo, newKey, oldKeyForChange) < 0) {
            mifare_desfire_key_free(newKey);
            mifare_desfire_key_free(oldMaster);
            throw std::runtime_error("Unable to change DESFire application key " + std::to_string(keyNo) + ".");
        }

        mifare_desfire_key_free(newKey);
    }

    mifare_desfire_key_free(oldMaster);

    const std::array<std::uint8_t, 16> readerKeyBytes = deriveAesKey(siteKeyHex, appAidHex, tagUidHex, cardUuidHex, 1);
    MifareDESFireKey readerKey = mifare_desfire_aes_key_new(const_cast<uint8_t*>(readerKeyBytes.data()));
    if (readerKey == nullptr) {
        throw std::runtime_error("Unable to allocate reader key.");
    }

    if (mifare_desfire_authenticate_aes(tag, 0x01, readerKey) < 0) {
        mifare_desfire_key_free(readerKey);
        throw std::runtime_error("Unable to authenticate with diversified reader key after key update.");
    }

    mifare_desfire_key_free(readerKey);
}

bool fileExists(MifareTag tag, uint8_t fileNumber) {
    uint8_t* files = nullptr;
    size_t count = 0;
    if (mifare_desfire_get_file_ids(tag, &files, &count) < 0) {
        throw std::runtime_error("Unable to enumerate DESFire files.");
    }

    bool found = false;
    for (size_t index = 0; index < count; ++index) {
        if (files[index] == fileNumber) {
            found = true;
            break;
        }
    }
    free(files);
    return found;
}

void ensureFiles(MifareTag tag) {
    if (!fileExists(tag, kIdentityFileNumber)) {
        const uint16_t accessRights = MDAR(MDAR_KEY1, MDAR_DENY, MDAR_KEY2, MDAR_KEY0);
        if (mifare_desfire_create_std_data_file(tag, kIdentityFileNumber, MDCM_ENCIPHERED, accessRights, kIdentityRecordSize) < 0) {
            throw std::runtime_error("Unable to create DESFire identity file.");
        }
    }

    if (!fileExists(tag, kMetadataFileNumber)) {
        const uint16_t accessRights = MDAR(MDAR_KEY2, MDAR_KEY2, MDAR_KEY2, MDAR_KEY0);
        if (mifare_desfire_create_std_data_file(tag, kMetadataFileNumber, MDCM_ENCIPHERED, accessRights, kMetadataFileSize) < 0) {
            throw std::runtime_error("Unable to create DESFire metadata file.");
        }
    }
}
#endif
}

bool DesfireClient::canUseHardware() const {
#if defined(PIDESFIRE_HAS_LIBNFC) && defined(PIDESFIRE_HAS_LIBFREEFARE)
    return true;
#else
    return false;
#endif
}

std::string DesfireClient::capabilitySummary() const {
    if (canUseHardware()) {
        return "libnfc and libfreefare detected; hardware operations can be implemented in this build.";
    }

    return "Building in skeleton mode without libnfc/libfreefare integration.";
}

IdentityRecord DesfireClient::prepareIdentityRecord() const {
    std::random_device randomDevice;
    std::mt19937 generator(randomDevice());
    std::uniform_int_distribution<int> byteDistribution(0, 255);

    std::ostringstream uuid;
    for (int index = 0; index < 16; ++index) {
        uuid << std::hex << std::setw(2) << std::setfill('0') << byteDistribution(generator);
    }

    IdentityRecord record;
    record.cardUuidHex = uuid.str();
    record.issueCounter = 1;
    record.flags = 0;
    return record;
}

std::vector<std::uint8_t> DesfireClient::encodeIdentityRecord(const IdentityRecord& identity) const {
    const std::vector<std::uint8_t> uuidBytes = hexToBytes(identity.cardUuidHex);
    if (uuidBytes.size() != 16) {
        throw std::runtime_error("card_uuid must encode exactly 16 bytes.");
    }

    std::vector<std::uint8_t> encoded(kIdentityRecordSize, 0x00);
    encoded[0] = kFormatVersion;
    std::copy(uuidBytes.begin(), uuidBytes.end(), encoded.begin() + 1);
    encoded[17] = static_cast<std::uint8_t>((identity.issueCounter >> 24) & 0xFF);
    encoded[18] = static_cast<std::uint8_t>((identity.issueCounter >> 16) & 0xFF);
    encoded[19] = static_cast<std::uint8_t>((identity.issueCounter >> 8) & 0xFF);
    encoded[20] = static_cast<std::uint8_t>(identity.issueCounter & 0xFF);
    encoded[21] = identity.flags;
    return encoded;
}

IdentityRecord DesfireClient::decodeIdentityRecord(const std::vector<std::uint8_t>& bytes) const {
    if (bytes.size() != kIdentityRecordSize) {
        throw std::runtime_error("Identity file must be exactly 32 bytes.");
    }
    if (bytes[0] != kFormatVersion) {
        throw std::runtime_error("Unsupported identity record format version.");
    }

    IdentityRecord record;
    record.cardUuidHex = bytesToHex(bytes.data() + 1, 16);
    record.issueCounter =
        (static_cast<std::uint32_t>(bytes[17]) << 24) |
        (static_cast<std::uint32_t>(bytes[18]) << 16) |
        (static_cast<std::uint32_t>(bytes[19]) << 8) |
        static_cast<std::uint32_t>(bytes[20]);
    record.flags = bytes[21];
    return record;
}

std::vector<std::string> DesfireClient::provisionPlan(const IdentityRecord& identity) const {
    return {
        "Select or create DESFire application AID D15F01",
        "Configure AES Key 0, Key 1, and Key 2",
        "Create File 01 for the 32-byte identity record",
        "Optionally create File 02 for administrative metadata",
        "Write card_uuid=" + identity.cardUuidHex,
        "Read back File 01 and verify the record contents"
    };
}

ProvisionedCard DesfireClient::provisionCard(const IdentityRecord& identity, const std::string& appAidHex, const std::string& siteKeyHex, const std::string& deviceName) const {
#if !defined(PIDESFIRE_HAS_LIBNFC) || !defined(PIDESFIRE_HAS_LIBFREEFARE)
    (void)identity;
    (void)appAidHex;
    (void)siteKeyHex;
    (void)deviceName;
    throw std::runtime_error("This build does not include libnfc/libfreefare support.");
#else
    if (siteKeyHex.empty()) {
        throw std::runtime_error("site_key_hex must be configured before provisioning a real card.");
    }

    NfcContext context;
    TagSession session = openDesfireTag(context.get(), deviceName);
    MifareTag tag = session.tag();

    char* tagUid = freefare_get_tag_uid(tag);
    if (tagUid == nullptr) {
        throw std::runtime_error("Unable to read tag UID.");
    }
    const std::string tagUidHex = tagUid;
    free(tagUid);

    ensureDefaultPiccAuth(tag);
    ensureApplication(tag, appAidHex);
    selectApplication(tag, appAidHex);
    configureKeys(tag, siteKeyHex, appAidHex, tagUidHex, identity.cardUuidHex);
    ensureFiles(tag);

    const std::vector<std::uint8_t> encoded = encodeIdentityRecord(identity);
    if (mifare_desfire_write_data_ex(tag, kIdentityFileNumber, 0, encoded.size(), encoded.data(), MDCM_ENCIPHERED) < 0) {
        throw std::runtime_error("Unable to write DESFire identity file.");
    }

    std::vector<std::uint8_t> readBack(encoded.size(), 0x00);
    if (mifare_desfire_read_data_ex(tag, kIdentityFileNumber, 0, readBack.size(), readBack.data(), MDCM_ENCIPHERED) < 0) {
        throw std::runtime_error("Unable to read back DESFire identity file.");
    }

    const IdentityRecord decoded = decodeIdentityRecord(readBack);
    if (decoded.cardUuidHex != identity.cardUuidHex || decoded.issueCounter != identity.issueCounter || decoded.flags != identity.flags) {
        throw std::runtime_error("Read-back verification failed for DESFire identity file.");
    }

    ProvisionedCard card;
    card.tagUidHex = tagUidHex;
    card.identity = decoded;
    return card;
#endif
}