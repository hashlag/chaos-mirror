#include <gtest/gtest.h>
#include "TestHelpers/AssertThrowEx.hpp"

#include <array>
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <vector>

#include "Padding/PadderIso7816.hpp"
#include "Padding/Padder.hpp"
#include "Service/ChaosException.hpp"

using namespace Chaos::Padding;

TEST(PadIso7816Tests, PadTest)
{
    {
        std::array<uint8_t, 1> fact = {};
        std::array<uint8_t, 1> expected = { 0x80 };

        PadderIso7816::Pad(fact.begin(), fact.end());
        ASSERT_EQ(expected, fact);
    }

    {
        std::array<uint8_t, 7> fact = {};
        std::array<uint8_t, 7> expected =
        {
           0x80, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00
        };

        PadderIso7816::Pad(fact.begin(), fact.end());
        ASSERT_EQ(expected, fact);
    }

    {
        std::array<uint8_t, 10> fact = {};
        std::array<uint8_t, 10> expected =
        {
           0x80, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00
        };

        PadderIso7816::Pad(fact.begin(), fact.end());
        ASSERT_EQ(expected, fact);
    }

    for (int i = 1; i < 256; ++i)
    {
        std::vector<uint8_t> fact(i, 0xff);

        PadderIso7816::Pad(fact.begin(), fact.end());

        for (int j = 0; j < i; ++j)
        {
            ASSERT_EQ(j == 0 ? 0x80 : 0x00, fact[j]);
        }
    }
}

TEST(PadIso7816Tests, PadInvalidRangeTest)
{
    {
        std::array<uint8_t, 3> out = {};

        ASSERT_THROW_EX(PadderIso7816::Pad(out.begin(), out.begin()),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("PadderIso7816::Pad(): invalid range", ex.GetMessage());
                        });
    }
}

TEST(PadIso7816Tests, PadOutIteratorUsageTest)
{
    {
        std::array<uint8_t, 28> fact;
        fact.fill(0xff);

        std::array<uint8_t, 28> expected =
        {
            0xff, 0xff, 0xff,
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff
        };

        PadderIso7816::Pad(fact.begin() + 3, fact.end() - 3);
        ASSERT_EQ(expected, fact);
    }

    {
        std::array<uint8_t, 39> fact;
        fact.fill(0xff);

        std::array<uint8_t, 39> expected =
        {
            0xff, 0xff, 0xff,
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff
        };

        PadderIso7816::Pad(fact.begin() + 3, fact.end() - 3);
        ASSERT_EQ(expected, fact);
    }
}

template<typename Impl, typename OutputIt>
void PadThroughBase(const Padder<Impl> & padder, OutputIt begin, OutputIt end)
{
    padder.Pad(begin, end);
}

TEST(PadIso7816Tests, PadThroughBaseTest)
{
    {
        std::array<uint8_t, 5> fact;
        fact.fill(0xff);

        std::array<uint8_t, 5> expected =
        {
            0x80, 0x00, 0x00, 0x00, 0x00
        };

        const PadderIso7816 padder;
        PadThroughBase(padder, fact.begin(), fact.end());

        ASSERT_EQ(expected, fact);
    }
}

TEST(PadIso7816Tests, UnpadTest)
{
    {
        std::array<uint8_t, 1> data = { 0x80 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(1, result.PadSize_);
    }

    {
        std::array<uint8_t, 4> data = { 0xaa, 0xbb, 0x80, 0x00 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(2, result.PadSize_);
    }

    {
        std::array<uint8_t, 10> data = { 0xaa, 0xbb, 0xcc, 0x80, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(7, result.PadSize_);
    }

    {
        std::array<uint8_t, 10> data = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
                                         0xa6, 0xa7, 0xa8, 0x80 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(1, result.PadSize_);
    }

    {
        std::array<uint8_t, 10> data = { 0xa0, 0xa1, 0xa2, 0x80, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(7, result.PadSize_);
    }

    {
        std::array<uint8_t, 10> data = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(10, result.PadSize_);
    }

    {
        std::array<uint8_t, 4> data = { 0x80, 0x80, 0x00, 0x00 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(3, result.PadSize_);
    }

    {
        std::array<uint8_t, 200> data;
        data.fill(0x41);
        *std::prev(data.end()) = 0x80;

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(1, result.PadSize_);
    }

    {
        std::array<uint8_t, 200> data;
        data.fill(0x41);
        *std::prev(data.end(), 100) = 0x80;
        std::fill(data.end() - 99, data.end(), 0);

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(100, result.PadSize_);
    }

    {
        std::array<uint8_t, 255> data;
        data.fill(0);
        *data.begin() = 0x80;

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(255, result.PadSize_);
    }

    {
        std::array<uint8_t, 381> data;
        data.fill(0x9a);
        *std::prev(data.end(), 255) = 0x80;
        std::fill(data.end() - 254, data.end(), 0);

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(255, result.PadSize_);
    }
}

TEST(PadIso7816Tests, UnpadErrorTest)
{
    {
        std::array<uint8_t, 0> data = { };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 1> data = { 0x00 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 5> data = { 0xa0, 0xa1, 0xa2, 0x80, 0xff };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 5> data = { 0xa0, 0xa1, 0x00, 0x00, 0x00 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 5> data = { 0x80, 0x00, 0xa2, 0x00, 0x00 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 5> data = { 0xa0, 0x80, 0x03, 0x00, 0x00 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 1> data = { 0xff };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }

    {
        std::array<uint8_t, 2> data = { 0x00, 0x00 };

        auto result = PadderIso7816::ComputeUnpad(data.begin(), data.end());

        ASSERT_FALSE(result.IsOkay_);
        ASSERT_EQ(0, result.PadSize_);
    }
}

template<typename Impl, typename OutputIt>
auto ComputeUnpadThroughBase(const Padder<Impl> & padder, OutputIt begin, OutputIt end)
{
    return padder.ComputeUnpad(begin, end);
}

TEST(PadIso7816Tests, ComputeUnpadThroughBaseTest)
{
    {
        std::array<uint8_t, 5> data = { 0x80, 0x00, 0x00, 0x00, 0x00 };

        const PadderIso7816 padder;
        auto result = ComputeUnpadThroughBase(padder, data.begin(), data.end());

        ASSERT_TRUE(result.IsOkay_);
        ASSERT_EQ(5, result.PadSize_);
    }
}
