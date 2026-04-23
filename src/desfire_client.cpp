#include "desfire_client.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <thread>

#if defined(PIDESFIRE_HAS_OPENSSL)
#include <openssl/sha.h>
#endif

#if defined(PIDESFIRE_HAS_LIBNFC)
#include <nfc/nfc.h>
#endif

#if defined(PIDESFIRE_HAS_LIBFREEFARE)
#include <freefare.h>
#endif

namespace
{
constexpr std::size_t kIdentityRecordSize = 32;
constexpr uint8_t kFormatVersion = 0x01;
constexpr uint8_t kIdentityFileNumber = 0x01;
constexpr uint8_t kMetadataFileNumber = 0x02;
constexpr uint32_t kMetadataFileSize = 32;
constexpr uint8_t kApplicationKeyCount = 3;

std::vector<std::uint8_t> hexToBytes(const std::string& hex)
{
    if ((hex.size() % 2) != 0)
    {
        throw std::runtime_error("Hex value must have an even number of characters.");
    }

    std::vector<std::uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (std::size_t index = 0; index < hex.size(); index += 2)
    {
        const std::string byteString = hex.substr(index, 2);
        bytes.push_back(static_cast<std::uint8_t>(std::stoul(byteString, nullptr, 16)));
    }

    return bytes;
}

std::string bytesToHex(const std::uint8_t* data, std::size_t size)
{
    std::ostringstream output;
    for (std::size_t index = 0; index < size; ++index)
    {
        output << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[index]);
    }
    return output.str();
}

std::array<std::uint8_t, 16> deriveAesKey(const std::string& siteKeyHex, const std::string& appAidHex, const std::string& tagUidHex, const std::string& cardUuidHex, std::uint8_t keySlot)
{
    const std::string material = siteKeyHex + ":" + appAidHex + ":" + tagUidHex + ":" + cardUuidHex + ":" + std::to_string(static_cast<int>(keySlot));

#if defined(PIDESFIRE_HAS_OPENSSL)
    std::array<std::uint8_t, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const unsigned char*>(material.data()), material.size(), digest.data());

    std::array<std::uint8_t, 16> keyBytes{};
    std::copy_n(digest.begin(), keyBytes.size(), keyBytes.begin());
    return keyBytes;
#else
    std::array<std::uint8_t, 16> keyBytes{};
    for (std::size_t index = 0; index < keyBytes.size(); ++index)
    {
        keyBytes[index] = static_cast<std::uint8_t>((material[index % material.size()] + index) & 0xFF);
    }
    return keyBytes;
#endif
}

#if defined(PIDESFIRE_HAS_LIBNFC) && defined(PIDESFIRE_HAS_LIBFREEFARE)
class NfcContext
{
  public:
    NfcContext()
    {
        nfc_init(&context_);
        if (context_ == nullptr)
        {
            throw std::runtime_error("Failed to initialize libnfc context.");
        }
    }

    ~NfcContext()
    {
        if (context_ != nullptr)
        {
            nfc_exit(context_);
        }
    }

    nfc_context* get() const
    {
        return context_;
    }

  private:
    nfc_context* context_ = nullptr;
};

class TagSession
{
  public:
    TagSession(nfc_device* device, MifareTag* tags, MifareTag tag, bool disconnectDesfire)
        : device_(device), tags_(tags), tag_(tag), disconnectDesfire_(disconnectDesfire)
    {
    }

    ~TagSession()
    {
        if (disconnectDesfire_ && tag_ != nullptr)
        {
            mifare_desfire_disconnect(tag_);
        }
        if (tags_ != nullptr)
        {
            freefare_free_tags(tags_);
        }
        if (device_ != nullptr)
        {
            nfc_close(device_);
        }
    }

    MifareTag tag() const
    {
        return tag_;
    }

  private:
    nfc_device* device_;
    MifareTag* tags_;
    MifareTag tag_;
    bool disconnectDesfire_;
};

TagSession openAnyTag(nfc_context* context, const std::string& deviceName)
{
    const char* requestedDevice = deviceName == "default" ? nullptr : deviceName.c_str();
    nfc_device* device = nfc_open(context, requestedDevice);
    if (device == nullptr)
    {
        throw std::runtime_error("Unable to open NFC device.");
    }

    MifareTag* tags = freefare_get_tags(device);
    if (tags == nullptr)
    {
        nfc_close(device);
        throw std::runtime_error("Unable to enumerate NFC tags.");
    }

    if (tags[0] == nullptr)
    {
        freefare_free_tags(tags);
        nfc_close(device);
        throw std::runtime_error("No NFC card present on the reader.");
    }

    return TagSession(device, tags, tags[0], false);
};

TagSession openDesfireTag(nfc_context* context, const std::string& deviceName)
{
    const char* requestedDevice = deviceName == "default" ? nullptr : deviceName.c_str();
    nfc_device* device = nfc_open(context, requestedDevice);
    if (device == nullptr)
    {
        throw std::runtime_error("Unable to open NFC device.");
    }

    MifareTag* tags = freefare_get_tags(device);
    if (tags == nullptr)
    {
        nfc_close(device);
        throw std::runtime_error("Unable to enumerate NFC tags.");
    }

    MifareTag desfireTag = nullptr;
    for (std::size_t index = 0; tags[index] != nullptr; ++index)
    {
        if (freefare_get_tag_type(tags[index]) == DESFIRE)
        {
            desfireTag = tags[index];
            break;
        }
    }

    if (desfireTag == nullptr)
    {
        freefare_free_tags(tags);
        nfc_close(device);
        throw std::runtime_error("No DESFire card present on the reader.");
    }

    if (mifare_desfire_connect(desfireTag) < 0)
    {
        const std::string error = freefare_strerror(desfireTag);
        freefare_free_tags(tags);
        nfc_close(device);
        throw std::runtime_error("Unable to connect to DESFire card: " + error);
    }

    return TagSession(device, tags, desfireTag, true);
}

std::string formatHexByte(std::uint8_t value)
{
    std::ostringstream output;
    output << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(value);
    return output.str();
}

std::string formatHexWord(std::uint16_t value)
{
    std::ostringstream output;
    output << "0x" << std::hex << std::setw(4) << std::setfill('0') << value;
    return output.str();
}

std::string formatHexAID(MifareDESFireAID aid)
{
    std::ostringstream output;
    output << std::hex << std::setw(6) << std::setfill('0') << mifare_desfire_aid_get_aid(aid);
    return output.str();
}

std::string communicationModeName(std::uint8_t value)
{
    switch (value)
    {
    case MDCM_PLAIN:
        return "plain";
    case MDCM_MACED:
        return "maced";
    case MDCM_ENCIPHERED:
        return "enciphered";
    default:
        return "unknown";
    }
}

std::string fileTypeName(std::uint8_t value)
{
    switch (value)
    {
    case MDFT_STANDARD_DATA_FILE:
        return "standard-data";
    case MDFT_BACKUP_DATA_FILE:
        return "backup-data";
    case MDFT_VALUE_FILE_WITH_BACKUP:
        return "value";
    case MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
        return "linear-record";
    case MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:
        return "cyclic-record";
    default:
        return "unknown";
    }
}

std::string desfireError(MifareTag tag, const std::string& fallback)
{
    const char* error = freefare_strerror(tag);
    if (error != nullptr && std::strlen(error) > 0)
    {
        return error;
    }
    return fallback;
}

MifareDESFireAID aidFromHex(const std::string& appAidHex)
{
    return mifare_desfire_aid_new(static_cast<uint32_t>(std::stoul(appAidHex, nullptr, 16)));
}

std::string ensureDefaultPiccAuth(MifareTag tag)
{
    std::array<uint8_t, 16> zeroAesKey{};
    MifareDESFireKey aesKey = mifare_desfire_aes_key_new(zeroAesKey.data());
    if (aesKey == nullptr)
    {
        throw std::runtime_error("Unable to allocate default AES PICC key.");
    }

    const int aesAuthResult = mifare_desfire_authenticate_aes(tag, 0, aesKey);
    mifare_desfire_key_free(aesKey);
    if (aesAuthResult == 0)
    {
        return "AES";
    }

    std::array<uint8_t, 8> zeroDesKey{};
    MifareDESFireKey desKey = mifare_desfire_des_key_new(zeroDesKey.data());
    if (desKey == nullptr)
    {
        throw std::runtime_error("Unable to allocate default DES PICC key.");
    }

    const int desAuthResult = mifare_desfire_authenticate(tag, 0, desKey);
    mifare_desfire_key_free(desKey);
    if (desAuthResult == 0)
    {
        return "DES";
    }

    std::array<uint8_t, 16> zero3DesKey{};
    MifareDESFireKey threeDesKey = mifare_desfire_3des_key_new(zero3DesKey.data());
    if (threeDesKey == nullptr)
    {
        throw std::runtime_error("Unable to allocate default 3DES PICC key.");
    }

    const int threeDesAuthResult = mifare_desfire_authenticate(tag, 0, threeDesKey);
    mifare_desfire_key_free(threeDesKey);
    if (threeDesAuthResult == 0)
    {
        return "3DES";
    }

    throw std::runtime_error(
        "Unable to authenticate with the factory-default PICC master key using AES, DES, or 3DES. "
        "This card is likely not blank or uses a non-default PICC key.");
}

bool applicationExists(MifareTag tag, const std::string& appAidHex)
{
    MifareDESFireAID* aids = nullptr;
    size_t count = 0;
    if (mifare_desfire_get_application_ids(tag, &aids, &count) < 0)
    {
        throw std::runtime_error("Unable to enumerate DESFire applications.");
    }

    const uint32_t desiredAid = static_cast<uint32_t>(std::stoul(appAidHex, nullptr, 16));
    bool found = false;
    for (size_t index = 0; index < count; ++index)
    {
        if (mifare_desfire_aid_get_aid(aids[index]) == desiredAid)
        {
            found = true;
            break;
        }
    }
    mifare_desfire_free_application_ids(aids);
    return found;
}

void ensureApplication(MifareTag tag, const std::string& appAidHex)
{
    if (applicationExists(tag, appAidHex))
    {
        return;
    }

    MifareDESFireAID aid = aidFromHex(appAidHex);
    if (aid == nullptr)
    {
        throw std::runtime_error("Unable to allocate DESFire AID.");
    }

    const uint8_t keySettings = 0x0F;
    const uint8_t keyCount = static_cast<uint8_t>(APPLICATION_CRYPTO_AES | kApplicationKeyCount);
    if (mifare_desfire_create_application_aes(tag, aid, keySettings, keyCount) < 0)
    {
        throw std::runtime_error("Unable to create DESFire application.");
    }
}

void deleteApplicationIfExists(MifareTag tag, const std::string& appAidHex)
{
    if (!applicationExists(tag, appAidHex))
    {
        return;
    }

    MifareDESFireAID aid = aidFromHex(appAidHex);
    if (aid == nullptr)
    {
        throw std::runtime_error("Unable to allocate DESFire AID.");
    }

    if (mifare_desfire_delete_application(tag, aid) < 0)
    {
        throw std::runtime_error("Unable to delete existing DESFire application " + appAidHex + ": " + desfireError(tag, "delete_application failed"));
    }
}

void selectApplication(MifareTag tag, const std::string& appAidHex)
{
    MifareDESFireAID aid = aidFromHex(appAidHex);
    if (aid == nullptr)
    {
        throw std::runtime_error("Unable to allocate DESFire AID.");
    }
    if (mifare_desfire_select_application(tag, aid) < 0)
    {
        throw std::runtime_error("Unable to select DESFire application.");
    }
}

bool fileExists(MifareTag tag, uint8_t fileNumber);

void ensureBootstrapFiles(MifareTag tag)
{
    if (!fileExists(tag, kIdentityFileNumber))
    {
        const uint16_t accessRights = MDAR(MDAR_FREE, MDAR_FREE, MDAR_FREE, MDAR_KEY0);
        if (mifare_desfire_create_std_data_file(tag, kIdentityFileNumber, MDCM_PLAIN, accessRights, kIdentityRecordSize) < 0)
        {
            throw std::runtime_error("Unable to create bootstrap DESFire identity file: " + desfireError(tag, "create_std_data_file failed"));
        }
    }
}

void finalizeFiles(MifareTag tag)
{
    const uint16_t identityAccessRights = MDAR(MDAR_FREE, MDAR_DENY, MDAR_KEY2, MDAR_KEY0);
    if (mifare_desfire_change_file_settings(tag, kIdentityFileNumber, MDCM_PLAIN, identityAccessRights) < 0)
    {
        throw std::runtime_error("Unable to finalize DESFire identity file settings: " + desfireError(tag, "change_file_settings failed"));
    }

    if (!fileExists(tag, kMetadataFileNumber))
    {
        const uint16_t metadataAccessRights = MDAR(MDAR_KEY2, MDAR_KEY2, MDAR_KEY2, MDAR_KEY0);
        if (mifare_desfire_create_std_data_file(tag, kMetadataFileNumber, MDCM_ENCIPHERED, metadataAccessRights, kMetadataFileSize) < 0)
        {
            throw std::runtime_error("Unable to create DESFire metadata file: " + desfireError(tag, "create_std_data_file failed"));
        }
    }
}

void configureKeys(MifareTag tag, const std::string& siteKeyHex, const std::string& appAidHex, const std::string& tagUidHex, const std::string& cardUuidHex)
{
    std::array<uint8_t, 16> zeroKey{};
    MifareDESFireKey oldMaster = mifare_desfire_aes_key_new(zeroKey.data());
    if (oldMaster == nullptr)
    {
        throw std::runtime_error("Unable to allocate old app master key.");
    }

    if (mifare_desfire_authenticate_aes(tag, 0, oldMaster) < 0)
    {
        mifare_desfire_key_free(oldMaster);
        throw std::runtime_error("Unable to authenticate to the new DESFire application with the default AES app master key.");
    }

    for (uint8_t keyNo = 1; keyNo < kApplicationKeyCount; ++keyNo)
    {
        const std::array<std::uint8_t, 16> material = deriveAesKey(siteKeyHex, appAidHex, tagUidHex, cardUuidHex, keyNo);
        MifareDESFireKey newKey = mifare_desfire_aes_key_new(const_cast<uint8_t*>(material.data()));
        if (newKey == nullptr)
        {
            mifare_desfire_key_free(oldMaster);
            throw std::runtime_error("Unable to allocate diversified AES key.");
        }

        if (mifare_desfire_change_key(tag, keyNo, newKey, nullptr) < 0)
        {
            mifare_desfire_key_free(newKey);
            mifare_desfire_key_free(oldMaster);
            throw std::runtime_error(
                "Unable to change DESFire application key " + std::to_string(keyNo) + ": " + desfireError(tag, "change_key failed"));
        }

        mifare_desfire_key_free(newKey);
    }

    const std::array<std::uint8_t, 16> readerKeyBytes = deriveAesKey(siteKeyHex, appAidHex, tagUidHex, cardUuidHex, 1);
    MifareDESFireKey readerKey = mifare_desfire_aes_key_new(const_cast<uint8_t*>(readerKeyBytes.data()));
    if (readerKey == nullptr)
    {
        throw std::runtime_error("Unable to allocate reader key.");
    }

    if (mifare_desfire_authenticate_aes(tag, 0x01, readerKey) < 0)
    {
        mifare_desfire_key_free(readerKey);
        throw std::runtime_error("Unable to authenticate with diversified reader key after key update: " + desfireError(tag, "authenticate_aes failed"));
    }

    mifare_desfire_key_free(readerKey);

    const std::array<std::uint8_t, 16> writerKeyBytes = deriveAesKey(siteKeyHex, appAidHex, tagUidHex, cardUuidHex, 2);
    MifareDESFireKey writerKey = mifare_desfire_aes_key_new(const_cast<uint8_t*>(writerKeyBytes.data()));
    if (writerKey == nullptr)
    {
        throw std::runtime_error("Unable to allocate writer key.");
    }

    if (mifare_desfire_authenticate_aes(tag, 0x02, writerKey) < 0)
    {
        mifare_desfire_key_free(writerKey);
        throw std::runtime_error("Unable to authenticate with diversified writer key after key update: " + desfireError(tag, "authenticate_aes failed"));
    }

    mifare_desfire_key_free(writerKey);

    if (mifare_desfire_authenticate_aes(tag, 0, oldMaster) < 0)
    {
        mifare_desfire_key_free(oldMaster);
        throw std::runtime_error("Unable to re-authenticate with the default AES app master key before rotating key 0.");
    }

    const std::array<std::uint8_t, 16> masterKeyBytes = deriveAesKey(siteKeyHex, appAidHex, tagUidHex, cardUuidHex, 0);
    MifareDESFireKey newMaster = mifare_desfire_aes_key_new(const_cast<uint8_t*>(masterKeyBytes.data()));
    if (newMaster == nullptr)
    {
        mifare_desfire_key_free(oldMaster);
        throw std::runtime_error("Unable to allocate new DESFire application master key.");
    }

    if (mifare_desfire_change_key(tag, 0, newMaster, oldMaster) < 0)
    {
        mifare_desfire_key_free(newMaster);
        mifare_desfire_key_free(oldMaster);
        throw std::runtime_error("Unable to change DESFire application key 0: " + desfireError(tag, "change_key failed"));
    }

    if (mifare_desfire_authenticate_aes(tag, 0, newMaster) < 0)
    {
        mifare_desfire_key_free(newMaster);
        mifare_desfire_key_free(oldMaster);
        throw std::runtime_error("Key 0 was updated, but re-authentication with the new DESFire application master key failed: " + desfireError(tag, "authenticate_aes failed"));
    }

    mifare_desfire_key_free(newMaster);
    mifare_desfire_key_free(oldMaster);
}

bool fileExists(MifareTag tag, uint8_t fileNumber)
{
    uint8_t* files = nullptr;
    size_t count = 0;
    if (mifare_desfire_get_file_ids(tag, &files, &count) < 0)
    {
        throw std::runtime_error("Unable to enumerate DESFire files.");
    }

    bool found = false;
    for (size_t index = 0; index < count; ++index)
    {
        if (files[index] == fileNumber)
        {
            found = true;
            break;
        }
    }
    free(files);
    return found;
}

#endif
} // namespace

bool DesfireClient::canUseHardware() const
{
#if defined(PIDESFIRE_HAS_LIBNFC) && defined(PIDESFIRE_HAS_LIBFREEFARE)
    return true;
#else
    return false;
#endif
}

std::string DesfireClient::capabilitySummary() const
{
    if (canUseHardware())
    {
        return "libnfc and libfreefare detected; hardware operations can be implemented in this build.";
    }

    return "Building in skeleton mode without libnfc/libfreefare integration.";
}

IdentityRecord DesfireClient::prepareIdentityRecord() const
{
    std::random_device randomDevice;
    std::mt19937 generator(randomDevice());
    std::uniform_int_distribution<int> byteDistribution(0, 255);

    std::ostringstream uuid;
    for (int index = 0; index < 16; ++index)
    {
        uuid << std::hex << std::setw(2) << std::setfill('0') << byteDistribution(generator);
    }

    IdentityRecord record;
    record.cardUuidHex = uuid.str();
    record.issueCounter = 1;
    record.flags = 0;
    return record;
}

std::vector<std::uint8_t> DesfireClient::encodeIdentityRecord(const IdentityRecord& identity) const
{
    const std::vector<std::uint8_t> uuidBytes = hexToBytes(identity.cardUuidHex);
    if (uuidBytes.size() != 16)
    {
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

IdentityRecord DesfireClient::decodeIdentityRecord(const std::vector<std::uint8_t>& bytes) const
{
    if (bytes.size() != kIdentityRecordSize)
    {
        throw std::runtime_error("Identity file must be exactly 32 bytes.");
    }
    if (bytes[0] != kFormatVersion)
    {
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

std::vector<std::string> DesfireClient::provisionPlan(const IdentityRecord& identity) const
{
    return {
        "Select or create DESFire application AID D15F01",
        "Configure AES Key 0, Key 1, and Key 2",
        "Create File 01 for the 32-byte identity record",
        "Optionally create File 02 for administrative metadata",
        "Write card_uuid=" + identity.cardUuidHex,
        "Read back File 01 and verify the record contents"};
}

ProvisionedCard DesfireClient::provisionCard(const IdentityRecord& identity, const std::string& appAidHex, const std::string& siteKeyHex, const std::string& deviceName) const
{
#if !defined(PIDESFIRE_HAS_LIBNFC) || !defined(PIDESFIRE_HAS_LIBFREEFARE)
    (void)identity;
    (void)appAidHex;
    (void)siteKeyHex;
    (void)deviceName;
    throw std::runtime_error("This build does not include libnfc/libfreefare support.");
#else
    if (siteKeyHex.empty())
    {
        throw std::runtime_error("site_key_hex must be configured before provisioning a real card.");
    }

    NfcContext context;
    TagSession session = openDesfireTag(context.get(), deviceName);
    MifareTag tag = session.tag();

    char* tagUid = freefare_get_tag_uid(tag);
    if (tagUid == nullptr)
    {
        throw std::runtime_error("Unable to read tag UID.");
    }
    const std::string tagUidHex = tagUid;
    free(tagUid);

    const std::string piccAuthMode = ensureDefaultPiccAuth(tag);
    std::cout << "Authenticated with factory-default PICC key using " << piccAuthMode << ".\n";
    deleteApplicationIfExists(tag, appAidHex);
    ensureApplication(tag, appAidHex);
    selectApplication(tag, appAidHex);
    ensureBootstrapFiles(tag);

    const std::vector<std::uint8_t> encoded = encodeIdentityRecord(identity);
    if (mifare_desfire_write_data_ex(tag, kIdentityFileNumber, 0, encoded.size(), encoded.data(), MDCM_PLAIN) < 0)
    {
        throw std::runtime_error("Unable to write DESFire identity file: " + desfireError(tag, "write_data_ex failed"));
    }

    std::vector<std::uint8_t> readBack(encoded.size(), 0x00);
    if (mifare_desfire_read_data_ex(tag, kIdentityFileNumber, 0, readBack.size(), readBack.data(), MDCM_PLAIN) < 0)
    {
        throw std::runtime_error("Unable to read back DESFire identity file: " + desfireError(tag, "read_data_ex failed"));
    }

    const IdentityRecord decoded = decodeIdentityRecord(readBack);
    if (decoded.cardUuidHex != identity.cardUuidHex || decoded.issueCounter != identity.issueCounter || decoded.flags != identity.flags)
    {
        throw std::runtime_error("Read-back verification failed for DESFire identity file.");
    }

    configureKeys(tag, siteKeyHex, appAidHex, tagUidHex, identity.cardUuidHex);
    finalizeFiles(tag);

    ProvisionedCard card;
    card.tagUidHex = tagUidHex;
    card.identity = decoded;
    return card;
#endif
}

CardInspectResult DesfireClient::inspectCard(const std::string& appAidHex, const std::string& deviceName) const
{
#if !defined(PIDESFIRE_HAS_LIBNFC) || !defined(PIDESFIRE_HAS_LIBFREEFARE)
    (void)appAidHex;
    (void)deviceName;
    throw std::runtime_error("This build does not include libnfc/libfreefare support.");
#else
    NfcContext context;
    TagSession session = openAnyTag(context.get(), deviceName);
    MifareTag tag = session.tag();

    CardInspectResult result;
    result.tagFriendlyName = freefare_get_tag_friendly_name(tag);

    switch (freefare_get_tag_type(tag))
    {
    case ULTRALIGHT:
        result.tagType = "ULTRALIGHT";
        break;
    case ULTRALIGHT_C:
        result.tagType = "ULTRALIGHT_C";
        break;
    case CLASSIC_1K:
        result.tagType = "CLASSIC_1K";
        break;
    case CLASSIC_4K:
        result.tagType = "CLASSIC_4K";
        break;
    case DESFIRE:
        result.tagType = "DESFIRE";
        result.isDesfire = true;
        break;
    default:
        result.tagType = "UNKNOWN";
        break;
    }

    char* rawUid = freefare_get_tag_uid(tag);
    if (rawUid != nullptr)
    {
        result.tagUidHex = rawUid;
        free(rawUid);
    }

    if (!result.isDesfire)
    {
        result.details.push_back("DESFire inspection: not available for this card type.");
        return result;
    }

    if (mifare_desfire_connect(tag) < 0)
    {
        result.details.push_back("DESFire connect failed: " + desfireError(tag, "connect error"));
        return result;
    }

    try
    {
        struct mifare_desfire_version_info versionInfo{};
        if (mifare_desfire_get_version(tag, &versionInfo) == 0)
        {
            result.details.push_back(
                "version: hw vendor=" + formatHexByte(versionInfo.hardware.vendor_id) +
                " type=" + formatHexByte(versionInfo.hardware.type) +
                " subtype=" + formatHexByte(versionInfo.hardware.subtype) +
                " version=" + std::to_string(versionInfo.hardware.version_major) + "." + std::to_string(versionInfo.hardware.version_minor) +
                " storage=" + formatHexByte(versionInfo.hardware.storage_size) +
                " protocol=" + formatHexByte(versionInfo.hardware.protocol));
            result.details.push_back(
                "version: sw vendor=" + formatHexByte(versionInfo.software.vendor_id) +
                " type=" + formatHexByte(versionInfo.software.type) +
                " subtype=" + formatHexByte(versionInfo.software.subtype) +
                " version=" + std::to_string(versionInfo.software.version_major) + "." + std::to_string(versionInfo.software.version_minor) +
                " storage=" + formatHexByte(versionInfo.software.storage_size) +
                " protocol=" + formatHexByte(versionInfo.software.protocol));
            result.details.push_back(
                "version UID: " + bytesToHex(versionInfo.uid, sizeof(versionInfo.uid)) +
                ", batch=" + bytesToHex(versionInfo.batch_number, sizeof(versionInfo.batch_number)) +
                ", production=" + std::to_string(versionInfo.production_week) + "/" + std::to_string(versionInfo.production_year));
        }
        else
        {
            result.details.push_back("version: unavailable (" + desfireError(tag, "read error") + ")");
        }

        uint32_t freeMemory = 0;
        if (mifare_desfire_free_mem(tag, &freeMemory) == 0)
        {
            result.details.push_back("free memory: " + std::to_string(freeMemory) + " bytes");
        }
        else
        {
            result.details.push_back("free memory: unavailable (" + desfireError(tag, "read error") + ")");
        }

        char* cardUid = nullptr;
        if (mifare_desfire_get_card_uid(tag, &cardUid) == 0 && cardUid != nullptr)
        {
            result.details.push_back("desfire card UID: " + std::string(cardUid));
            free(cardUid);
        }
        else
        {
            result.details.push_back("desfire card UID: unavailable (likely requires authentication)");
        }

        uint8_t keySettings = 0;
        uint8_t maxKeys = 0;
        if (mifare_desfire_get_key_settings(tag, &keySettings, &maxKeys) == 0)
        {
            result.details.push_back("PICC key settings: settings=" + formatHexByte(keySettings) + ", max_keys=" + std::to_string(maxKeys));
        }
        else
        {
            result.details.push_back("PICC key settings: unavailable (" + desfireError(tag, "read error") + ")");
        }

        MifareDESFireAID* aids = nullptr;
        size_t aidCount = 0;
        if (mifare_desfire_get_application_ids(tag, &aids, &aidCount) == 0)
        {
            result.details.push_back("applications: " + std::to_string(aidCount));
            for (size_t index = 0; index < aidCount; ++index)
            {
                result.details.push_back("  AID " + formatHexAID(aids[index]));
            }
            mifare_desfire_free_application_ids(aids);
        }
        else
        {
            result.details.push_back("applications: unavailable (" + desfireError(tag, "read error") + ")");
        }

        if (applicationExists(tag, appAidHex))
        {
            result.details.push_back("configured app " + appAidHex + ": present");
            selectApplication(tag, appAidHex);

            uint8_t* files = nullptr;
            size_t fileCount = 0;
            if (mifare_desfire_get_file_ids(tag, &files, &fileCount) == 0)
            {
                result.details.push_back("configured app files: " + std::to_string(fileCount));
                for (size_t index = 0; index < fileCount; ++index)
                {
                    struct mifare_desfire_file_settings fileSettings{};
                    if (mifare_desfire_get_file_settings(tag, files[index], &fileSettings) == 0)
                    {
                        std::string line =
                            "  file " + formatHexByte(files[index]) +
                            ": type=" + fileTypeName(fileSettings.file_type) +
                            ", comm=" + communicationModeName(fileSettings.communication_settings) +
                            ", access=" + formatHexWord(fileSettings.access_rights);

                        if (fileSettings.file_type == MDFT_STANDARD_DATA_FILE || fileSettings.file_type == MDFT_BACKUP_DATA_FILE)
                        {
                            line += ", size=" + std::to_string(fileSettings.settings.standard_file.file_size);
                        }

                        result.details.push_back(line);
                    }
                    else
                    {
                        result.details.push_back("  file " + formatHexByte(files[index]) + ": settings unavailable (" + desfireError(tag, "read error") + ")");
                    }
                }
                free(files);
            }
            else
            {
                result.details.push_back("configured app files: unavailable (" + desfireError(tag, "read error") + ")");
            }

            std::vector<std::uint8_t> data(kIdentityRecordSize, 0x00);
            if (mifare_desfire_read_data_ex(tag, kIdentityFileNumber, 0, kIdentityRecordSize, data.data(), MDCM_PLAIN) >= 0)
            {
                try
                {
                    const IdentityRecord identity = decodeIdentityRecord(data);
                    result.details.push_back("configured app identity: card_uuid=" + identity.cardUuidHex + ", issue_counter=" + std::to_string(identity.issueCounter) + ", flags=" + std::to_string(identity.flags));
                }
                catch (const std::exception& exception)
                {
                    result.details.push_back("configured app identity: unreadable format (" + std::string(exception.what()) + ")");
                }
            }
            else
            {
                result.details.push_back("configured app identity: unavailable (" + desfireError(tag, "read error") + ")");
            }
        }
        else
        {
            result.details.push_back("configured app " + appAidHex + ": not present");
        }
    }
    catch (...)
    {
        mifare_desfire_disconnect(tag);
        throw;
    }

    mifare_desfire_disconnect(tag);
    return result;
#endif
}

CardScanResult DesfireClient::readCardIdentity(const std::string& appAidHex, const std::string& deviceName) const
{
#if !defined(PIDESFIRE_HAS_LIBNFC) || !defined(PIDESFIRE_HAS_LIBFREEFARE)
    (void)appAidHex;
    (void)deviceName;
    throw std::runtime_error("This build does not include libnfc/libfreefare support.");
#else
    NfcContext context;
    TagSession session = openDesfireTag(context.get(), deviceName);
    MifareTag tag = session.tag();

    char* rawUid = freefare_get_tag_uid(tag);
    if (rawUid == nullptr)
    {
        throw std::runtime_error("Unable to read tag UID.");
    }
    const std::string tagUidHex = rawUid;
    free(rawUid);

    CardScanResult result;
    result.tagUidHex = tagUidHex;

    if (!applicationExists(tag, appAidHex))
    {
        return result;
    }

    selectApplication(tag, appAidHex);

    std::vector<std::uint8_t> data(kIdentityRecordSize, 0x00);
    if (mifare_desfire_read_data_ex(tag, kIdentityFileNumber, 0, kIdentityRecordSize, data.data(), MDCM_PLAIN) >= 0)
    {
        try
        {
            result.identity = decodeIdentityRecord(data);
            result.hasIdentity = true;
        }
        catch (...)
        {
            // App exists but file is unreadable or format mismatch — treat as provisioned but opaque.
        }
    }

    return result;
#endif
}

bool DesfireClient::pollForAnyCard(const std::string& deviceName) const
{
#if !defined(PIDESFIRE_HAS_LIBNFC) || !defined(PIDESFIRE_HAS_LIBFREEFARE)
    (void)deviceName;
    return false;
#else
    try
    {
        NfcContext context;
        const char* requestedDevice = deviceName == "default" ? nullptr : deviceName.c_str();
        nfc_device* device = nfc_open(context.get(), requestedDevice);
        if (device == nullptr)
        {
            return false;
        }

        MifareTag* tags = freefare_get_tags(device);
        const bool found = tags != nullptr && tags[0] != nullptr;
        if (tags != nullptr)
        {
            freefare_free_tags(tags);
        }
        nfc_close(device);
        return found;
    }
    catch (...)
    {
        return false;
    }
#endif
}

bool DesfireClient::pollForCard(const std::string& deviceName) const
{
#if !defined(PIDESFIRE_HAS_LIBNFC) || !defined(PIDESFIRE_HAS_LIBFREEFARE)
    (void)deviceName;
    return false;
#else
    try
    {
        NfcContext context;
        const char* requestedDevice = deviceName == "default" ? nullptr : deviceName.c_str();
        nfc_device* device = nfc_open(context.get(), requestedDevice);
        if (device == nullptr)
        {
            return false;
        }

        MifareTag* tags = freefare_get_tags(device);
        bool found = false;
        if (tags != nullptr)
        {
            for (int index = 0; tags[index] != nullptr; ++index)
            {
                if (freefare_get_tag_type(tags[index]) == DESFIRE)
                {
                    found = true;
                    break;
                }
            }
            freefare_free_tags(tags);
        }
        nfc_close(device);
        return found;
    }
    catch (...)
    {
        return false;
    }
#endif
}

void DesfireClient::waitForAnyCardRemoval(const std::string& deviceName) const
{
    while (pollForAnyCard(deviceName))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }
}

void DesfireClient::waitForCardRemoval(const std::string& deviceName) const
{
    while (pollForCard(deviceName))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }
}