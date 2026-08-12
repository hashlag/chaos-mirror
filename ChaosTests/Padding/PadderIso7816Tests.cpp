#include <gtest/gtest.h>
#include "TestHelpers/AssertThrowEx.hpp"

#include <array>
#include <cstdint>
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
