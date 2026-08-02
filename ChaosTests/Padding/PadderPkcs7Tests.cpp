#include <gtest/gtest.h>
#include "TestHelpers/AssertThrowEx.hpp"

#include <array>
#include <cstdint>
#include <vector>

#include "Padding/PadderPkcs7.hpp"
#include "Padding/Padder.hpp"
#include "Service/ChaosException.hpp"

using namespace Chaos::Padding;

TEST(PadPkcs7Tests, PadTest)
{
    {
        std::array<uint8_t, 1> fact = {};
        std::array<uint8_t, 1> expected = { 0x01 };

        PadderPkcs7::Pad(fact.begin(), fact.end());
        ASSERT_EQ(expected, fact);
    }

    {
        std::array<uint8_t, 7> fact = {};
        std::array<uint8_t, 7> expected =
        {
           0x07, 0x07, 0x07, 0x07, 0x07,
           0x07, 0x07
        };

        PadderPkcs7::Pad(fact.begin(), fact.end());
        ASSERT_EQ(expected, fact);
    }

    {
        std::array<uint8_t, 10> fact = {};
        std::array<uint8_t, 10> expected =
        {
           0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
           0x0a, 0x0a, 0x0a, 0x0a, 0x0a
        };

        PadderPkcs7::Pad(fact.begin(), fact.end());
        ASSERT_EQ(expected, fact);
    }

    for (int i = 0; i < 256; ++i)
    {
        std::vector<uint8_t> fact(i, 0x00);

        PadderPkcs7::Pad(fact.begin(), fact.end());
        ASSERT_EQ(std::vector<uint8_t>(i, i), fact);
    }
}

TEST(PadPkcs7Tests, PadInvalidRangeTest)
{
    {
        std::array<uint8_t, 256> out = {};

        ASSERT_THROW_EX(PadderPkcs7::Pad(out.begin(), out.end()),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("PadderPkcs7::Pad(): invalid range", ex.GetMessage());
                        });
    }

    {
        std::array<uint8_t, 500> out = {};

        ASSERT_THROW_EX(PadderPkcs7::Pad(out.begin(), out.end()),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("PadderPkcs7::Pad(): invalid range", ex.GetMessage());
                        });
    }

    {
        std::array<uint8_t, 50> out = {};

        ASSERT_THROW_EX(PadderPkcs7::Pad(out.end(), out.begin()),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("PadderPkcs7::Pad(): invalid range", ex.GetMessage());
                        });
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

        PadderPkcs7::Pad(fact.begin() + 3, fact.end() - 3);
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

        PadderPkcs7::Pad(fact.begin() + 3, fact.end() - 3);
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

        PadderPkcs7::Pad(fact.begin() + 5, fact.begin() + 5);
        ASSERT_EQ(expected, fact);
    }
}

template<typename Impl, typename OutputIt>
void PadThroughBase(const Padder<Impl> & padder, OutputIt begin, OutputIt end)
{
    padder.Pad(begin, end);
}

TEST(PadPkcs7Tests, PadThroughBaseTest)
{
    {
        std::array<uint8_t, 5> fact = {};
        std::array<uint8_t, 5> expected =
        {
            0x05, 0x05, 0x05, 0x05, 0x05
        };

        const PadderPkcs7 padder;
        PadThroughBase(padder, fact.begin(), fact.end());

        ASSERT_EQ(expected, fact);
    }
}

TEST(PadPkcs7Tests, UnpadTest)
{
    {
        std::array<uint8_t, 1> data = { 0x01 };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(1, result.PadSize_);
    }

    {
        std::array<uint8_t, 4> data = { 0xaa, 0xbb, 0x02, 0x02 };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(2, result.PadSize_);
    }

    {
        std::array<uint8_t, 10> data = { 0xaa, 0xbb, 0xcc, 0x07, 0x07,
                                         0x07, 0x07, 0x07, 0x07, 0x07 };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(7, result.PadSize_);
    }

    {
        std::array<uint8_t, 10> data = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
                                         0xa6, 0xa7, 0xa8, 0x01 };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(1, result.PadSize_);
    }

    {
        std::array<uint8_t, 10> data = { 0xa0, 0xa1, 0xa2, 0x07, 0x07, 0x07,
                                         0x07, 0x07, 0x07, 0x07 };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(7, result.PadSize_);
    }

    {
        std::array<uint8_t, 10> data = { 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
                                         0x0a, 0x0a, 0x0a, 0x0a };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(10, result.PadSize_);
    }

    {
        std::array<uint8_t, 4> data = { 0x03, 0x03, 0x03, 0x03 };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(3, result.PadSize_);
    }

    {
        std::array<uint8_t, 200> data;
        data.fill(0x41);
        *std::prev(data.end()) = 1;

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(1, result.PadSize_);
    }

    {
        std::array<uint8_t, 200> data;
        data.fill(0x41);
        std::fill(data.end() - 100, data.end(), 100);

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(100, result.PadSize_);
    }

    {
        std::array<uint8_t, 255> data;
        data.fill(255);

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(255, result.PadSize_);
    }

    {
        std::array<uint8_t, 381> data;
        data.fill(0x9a);
        std::fill(data.end() - 255, data.end(), 255);

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(255, result.PadSize_);
    }
}

TEST(PadPkcs7Tests, UnpadErrorTest)
{
    {
        std::array<uint8_t, 0> data = { };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 1> data = { 0x00 };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 5> data = { 0xa0, 0xa1, 0xa2, 0xa3, 0xff };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 5> data = { 0xa0, 0xa1, 0xa2, 0xa3, 0x06 };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 5> data = { 0xa0, 0xa1, 0xa2, 0xa3, 0x05 };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 5> data = { 0xa0, 0xa1, 0x03, 0x02, 0x03 };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 1> data = { 0xff };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 2> data = { 0x03, 0x03 };

        auto result = PadderPkcs7::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }
}

template<typename Impl, typename OutputIt>
auto ComputeUnpadThroughBase(const Padder<Impl> & padder, OutputIt begin, OutputIt end)
{
    return padder.ComputeUnpad(begin, end);
}

TEST(PadPkcs7Tests, ComputeUnpadThroughBaseTest)
{
    {
        std::array<uint8_t, 5> data = { 0x05, 0x05, 0x05, 0x05, 0x05 };

        const PadderPkcs7 padder;
        auto result = ComputeUnpadThroughBase(padder, data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(5, result.PadSize_);
    }
}
