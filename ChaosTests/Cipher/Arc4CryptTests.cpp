#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <array>

#include "Cipher/Arc4/Arc4Crypt.hpp"
#include "Service/ChaosException.hpp"

using namespace Chaos::Cipher::Arc4;

static std::vector<uint8_t> StrToU8Vec(const char * str)
{
    std::vector<uint8_t> result;
    result.reserve(strlen(str));

    for (; *str != '\0'; ++str)
    {
        result.push_back(static_cast<uint8_t>(*str));
    }

    return result;
}

TEST(Arc4CryptTests, BasicTest)
{
    const std::vector<uint8_t> key = StrToU8Vec("Secret");
    const std::vector<uint8_t> data = StrToU8Vec("Attack at dawn");

    std::vector<uint8_t> ciphertext;
    ciphertext.resize(data.size());

    {
        Arc4Crypt arc4;
        arc4.Rekey(key.begin(), key.end());

        arc4.Encrypt(ciphertext.begin(), data.begin(), data.size());
    }

    ASSERT_EQ(std::vector<uint8_t>({ 0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B,
                                     0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5 }),
              ciphertext);

    std::vector<uint8_t> recoveredData;
    recoveredData.resize(data.size());

    {
        Arc4Crypt arc4;
        arc4.Rekey(key.begin(), key.end());

        arc4.Decrypt(recoveredData.begin(), ciphertext.begin(), ciphertext.size());
    }

    ASSERT_EQ(data, recoveredData);
}

TEST(Arc4CryptTests, UninitializedArc4CryptTest)
{
    Arc4Crypt arc4;

    {
        std::array<uint8_t, 10> in;
        in.fill(0);

        std::array<uint8_t, 10> out;
        out.fill(0);

        ASSERT_THROW(arc4.Encrypt(out.begin(), in.begin(), in.size()), Chaos::Service::ChaosException);
        ASSERT_THROW(arc4.Decrypt(out.begin(), in.begin(), in.size()), Chaos::Service::ChaosException);
    }
}

TEST(Arc4CryptTests, RekeyTest)
{
    Arc4Crypt arc4;

    const std::vector<uint8_t> data = StrToU8Vec("The quick brown fox jumps over the lazy dog.");

    {
        const std::vector<uint8_t> key = { 0x01, 0x02, 0x03, 0x04, 0x05 };

        std::vector<uint8_t> ciphertext;
        ciphertext.resize(data.size());

        arc4.Rekey(key.begin(), key.end());
        arc4.Encrypt(ciphertext.begin(), data.begin(), data.size());

        ASSERT_EQ(std::vector<uint8_t>({ 0xe6, 0x51, 0x06, 0x25, 0x81, 0x48, 0xa9, 0x44, 0xa7, 0xe3, 0x30,
                                         0x38, 0x65, 0x66, 0x76, 0x88, 0x0f, 0xed, 0xec, 0x6f, 0x72, 0x89,
                                         0xef, 0xa5, 0xfa, 0xe4, 0x6c, 0xd2, 0x1f, 0x7f, 0x29, 0x6d, 0xde,
                                         0xea, 0x58, 0xae, 0xec, 0x6f, 0xa1, 0x02, 0x47, 0x23, 0x0b, 0x96 }),
                  ciphertext);
    }

    {
        const std::vector<uint8_t> key = { 0x05, 0x04, 0x03, 0x02, 0x01 };

        std::vector<uint8_t> ciphertext;
        ciphertext.resize(data.size());

        arc4.Rekey(key.begin(), key.end());
        arc4.Encrypt(ciphertext.begin(), data.begin(), data.size());

        ASSERT_EQ(std::vector<uint8_t>({ 0x18, 0x4a, 0x2e, 0x05, 0xc2, 0x8e, 0x5b, 0x26, 0xfa, 0x47, 0x44,
                                         0x0d, 0x12, 0x28, 0xb4, 0x45, 0x06, 0xc3, 0x5a, 0x17, 0xeb, 0xad,
                                         0x60, 0xb2, 0x16, 0x17, 0x29, 0x4d, 0xaa, 0xcb, 0x27, 0xd1, 0x45,
                                         0xa8, 0xb9, 0xc0, 0x02, 0xd3, 0x4a, 0x9d, 0xe8, 0xde, 0x63, 0x30 }),
                  ciphertext);
    }
}

TEST(Arc4CryptTests, EncryptOutIteratorUsageTest)
{
    const std::vector<uint8_t> data = StrToU8Vec("The quick brown fox jumps over the lazy dog.");

    {
        std::array<uint8_t, 5> key = { 0x01, 0x02, 0x03, 0x04, 0x05 };

        Arc4Crypt crypt(key.begin(), key.end());

        std::array<uint8_t, 44> out;
        out.fill(0);

        std::array<uint8_t, 44> expected =
        {
            0xe6, 0x51, 0x06, 0x25, 0x81, 0x48, 0xa9, 0x44, 0xa7, 0xe3, 0x30,
            0x38, 0x65, 0x66, 0x76, 0x88, 0x0f, 0xed, 0xec, 0x6f, 0x72, 0x89,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        crypt.Encrypt(out.begin(), data.begin(), 22);

        ASSERT_EQ(expected, out);
    }

    {
        std::array<uint8_t, 5> key = { 0x01, 0x02, 0x03, 0x04, 0x05 };

        Arc4Crypt crypt(key.begin(), key.end());

        std::array<uint8_t, 44> out;
        out.fill(0);

        std::array<uint8_t, 44> expected =
        {
            0xe6, 0x51, 0x06, 0x25, 0x81, 0x48, 0xa9, 0x44, 0xa7, 0xe3, 0x30,
            0x38, 0x65, 0x66, 0x76, 0x88, 0x0f, 0xed, 0xec, 0x6f, 0x72, 0x89,
            0xef, 0xa5, 0xfa, 0xe4, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        crypt.Encrypt(out.begin(), data.begin(), 27);

        ASSERT_EQ(expected, out);
    }

    {
        std::array<uint8_t, 5> key = { 0x01, 0x02, 0x03, 0x04, 0x05 };

        Arc4Crypt crypt(key.begin(), key.end());

        std::array<uint8_t, 44> out;
        out.fill(0);

        std::array<uint8_t, 44> expected;
        expected.fill(0);

        crypt.Encrypt(out.begin(), data.begin(), 0);

        ASSERT_EQ(expected, out);
    }
}
