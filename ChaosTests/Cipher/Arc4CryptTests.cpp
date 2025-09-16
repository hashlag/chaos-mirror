#include <gtest/gtest.h>
#include <vector>
#include <string>

#include "Cipher/Arc4/Arc4Crypt.hpp"

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

static std::string U8VecToStr(const std::vector<uint8_t> & vec)
{
    std::string result;
    result.reserve(vec.size());

    for (auto it = vec.begin(); it != vec.end(); ++it)
    {
        result.push_back(static_cast<char>(*it));
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
