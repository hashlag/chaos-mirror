#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <vector>

#include "Padding/PadPkcs7.hpp"
#include "Service/ChaosException.hpp"

using namespace Chaos::Padding;

TEST(PadPkcs7Tests, PadTest)
{
    {
        std::array<uint8_t, 1> fact = {};
        std::array<uint8_t, 1> expected = { 0x01 };

        PadPkcs7::Pad(fact.begin(), fact.end());
        ASSERT_EQ(expected, fact);
    }

    {
        std::array<uint8_t, 7> fact = {};
        std::array<uint8_t, 7> expected =
        {
           0x07, 0x07, 0x07, 0x07, 0x07,
           0x07, 0x07
        };

        PadPkcs7::Pad(fact.begin(), fact.end());
        ASSERT_EQ(expected, fact);
    }

    {
        std::array<uint8_t, 10> fact = {};
        std::array<uint8_t, 10> expected =
        {
           0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
           0x0a, 0x0a, 0x0a, 0x0a, 0x0a
        };

        PadPkcs7::Pad(fact.begin(), fact.end());
        ASSERT_EQ(expected, fact);
    }

    for (int i = 0; i < 256; ++i)
    {
        std::vector<uint8_t> fact(i, 0x00);

        PadPkcs7::Pad(fact.begin(), fact.end());
        ASSERT_EQ(std::vector<uint8_t>(i, i), fact);
    }
}

TEST(PadPkcs7Tests, PadInvalidRangeTest)
{
    {
        std::array<uint8_t, 256> out = {};

        ASSERT_THROW(PadPkcs7::Pad(out.begin(), out.end()), Chaos::Service::ChaosException);
    }

    {
        std::array<uint8_t, 500> out = {};

        ASSERT_THROW(PadPkcs7::Pad(out.begin(), out.end()), Chaos::Service::ChaosException);
    }

    {
        std::array<uint8_t, 50> out = {};

        ASSERT_THROW(PadPkcs7::Pad(out.end(), out.begin()), Chaos::Service::ChaosException);
    }
}

TEST(PadPkcs7Tests, PadOutIteratorUsageTest)
{
    {
        std::array<uint8_t, 28> fact = {};
        std::array<uint8_t, 28> expected =
        {
            0x00, 0x00, 0x00,
            0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
            0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
            0x00, 0x00, 0x00
        };

        PadPkcs7::Pad(fact.begin() + 3, fact.end() - 3);
        ASSERT_EQ(expected, fact);
    }

    {
        std::array<uint8_t, 39> fact = {};
        std::array<uint8_t, 39> expected =
        {
            0x00, 0x00, 0x00,
            0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21,
            0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21,
            0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21, 0x21,
            0x00, 0x00, 0x00
        };

        PadPkcs7::Pad(fact.begin() + 3, fact.end() - 3);
        ASSERT_EQ(expected, fact);
    }

    {
        std::array<uint8_t, 10> fact =
        {
            0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
            0xbb, 0xbb, 0xbb, 0xbb, 0xbb
        };
        std::array<uint8_t, 10> expected =
        {
            0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
            0xbb, 0xbb, 0xbb, 0xbb, 0xbb
        };

        PadPkcs7::Pad(fact.begin() + 5, fact.begin() + 5);
        ASSERT_EQ(expected, fact);
    }
}
