#include "desfire_client.h"

#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace
{
int fail(const std::string& message)
{
    std::cerr << "FAIL: " << message << "\n";
    return 1;
}

bool expectThrow(const std::function<void()>& fn)
{
    try
    {
        fn();
        return false;
    }
    catch (const std::exception&)
    {
        return true;
    }
}
} // namespace

int main()
{
    DesfireClient client;

    const IdentityRecord expected{
        "00112233445566778899aabbccddeeff",
        0x11223344u,
        0x5Au};

    const std::vector<std::uint8_t> encoded = client.encodeIdentityRecord(expected);
    if (encoded.size() != 32)
    {
        return fail("Encoded identity record must be exactly 32 bytes.");
    }

    if (encoded[0] != 0x01)
    {
        return fail("Encoded format version must be 0x01.");
    }

    if (encoded[17] != 0x11 || encoded[18] != 0x22 || encoded[19] != 0x33 || encoded[20] != 0x44)
    {
        return fail("Issue counter must be big-endian in bytes 17..20.");
    }

    if (encoded[21] != 0x5A)
    {
        return fail("Flags byte must be stored at offset 21.");
    }

    const IdentityRecord decoded = client.decodeIdentityRecord(encoded);
    if (decoded.cardUuidHex != expected.cardUuidHex)
    {
        return fail("Decoded card UUID does not match encoded value.");
    }

    if (decoded.issueCounter != expected.issueCounter)
    {
        return fail("Decoded issue counter does not match encoded value.");
    }

    if (decoded.flags != expected.flags)
    {
        return fail("Decoded flags do not match encoded value.");
    }

    const bool badUuidLengthThrows = expectThrow([&client]()
                                                 {
        const IdentityRecord bad{"001122", 1u, 0u};
        (void)client.encodeIdentityRecord(bad); });
    if (!badUuidLengthThrows)
    {
        return fail("encodeIdentityRecord must reject UUIDs that are not 16 bytes.");
    }

    const bool badSizeThrows = expectThrow([&client]()
                                           {
        std::vector<std::uint8_t> bad(31, 0x00);
        (void)client.decodeIdentityRecord(bad); });
    if (!badSizeThrows)
    {
        return fail("decodeIdentityRecord must reject non-32-byte buffers.");
    }

    const bool badVersionThrows = expectThrow([&client, &encoded]()
                                              {
        std::vector<std::uint8_t> wrongVersion = encoded;
        wrongVersion[0] = 0x02;
        (void)client.decodeIdentityRecord(wrongVersion); });
    if (!badVersionThrows)
    {
        return fail("decodeIdentityRecord must reject unsupported format versions.");
    }

    std::cout << "PASS: identity record encode/decode tests\n";
    return 0;
}
