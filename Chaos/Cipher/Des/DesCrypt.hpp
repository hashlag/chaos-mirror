#ifndef CHAOS_CIPHER_DES_DESCRYPT_HPP
#define CHAOS_CIPHER_DES_DESCRYPT_HPP

#include <utility>

#include "Service/SeArray.hpp"

namespace Chaos::Cipher::Des::Inner_
{

struct Bitwise
{
    template<uint8_t BitsUsed>
    static uint8_t GetBit(uint64_t value, int_fast8_t bitNumber)
    {
        return (value >> (BitsUsed - bitNumber)) & 0b1;
    }

    template<uint8_t BitsUsed>
    static void SetBit(uint64_t & value, int_fast8_t bitNumber)
    {
        value |= (static_cast<uint64_t>(0b1) << (BitsUsed - bitNumber));
    }

    template<uint8_t BitsUsedIn, uint8_t BitsUsedOut, typename InputIt>
    static uint64_t TableChoice(uint64_t value, InputIt tableBegin, InputIt tableEnd)
    {
        uint64_t result = 0;

        int_fast8_t i = 1;
        for (InputIt it = tableBegin; it != tableEnd; ++it, ++i)
        {
            if (GetBit<BitsUsedIn>(value, *it))
            {
                SetBit<BitsUsedOut>(result, i);
            }
        }

        return result;
    }

    template<uint8_t Bits>
    static constexpr uint64_t Mask()
    {
        return (static_cast<uint64_t>(0b1) << Bits) - static_cast<uint64_t>(0b1);
    }

    template<uint8_t BitsUsed>
    static void Rotl(uint64_t & value, int_fast8_t shift)
    {
        value = ((value << shift) | (value >> (BitsUsed - shift))) & Mask<BitsUsed>();
    }

    template<uint8_t BitsUsedOut>
    static std::pair<uint64_t, uint64_t> Split(uint64_t value)
    {
        return { value >> BitsUsedOut, value & Mask<BitsUsedOut>() };
    }

    template<uint8_t BitsUsedIn>
    static uint64_t Merge(uint64_t lhs, uint64_t rhs)
    {
        return (lhs << BitsUsedIn) | rhs;
    }

    template<typename InputIt>
    static uint64_t PackUInt64(InputIt begin, InputIt end)
    {
        uint64_t result = 0;

        int_fast8_t i = 0;
        for (InputIt it = begin; i < 8 && it != end; ++i, ++it)
        {
            result |= static_cast<uint64_t>(*it) << (56 - (i * 8));
        }

        return result;
    }
};

using RawKeyArray = Service::SeArray<uint8_t, 8>;

class KeySchedule
{
public:
    using Key64 = uint64_t;
    using Key56 = uint64_t;

    using RoundKey48 = uint64_t;

    KeySchedule(const RawKeyArray & rawKeyArray)
    {
        Key56 key56 = Pc1(Bitwise::PackUInt64(rawKeyArray.Begin(), rawKeyArray.End()));

        auto [c28, d28] = Bitwise::Split<28>(key56);

        for (int_fast8_t i = 0; i < Schedule_.Size(); ++i)
        {
            if (i == 0 || i == 1 || i == 8 || i == 15)
            {
                Bitwise::Rotl<28>(c28, 1);
                Bitwise::Rotl<28>(d28, 1);
            }
            else
            {
                Bitwise::Rotl<28>(c28, 2);
                Bitwise::Rotl<28>(d28, 2);
            }

            Schedule_[i] = Pc2(Bitwise::Merge<28>(c28, d28));
        }
    }

    RoundKey48 operator[](int_fast8_t i) const
    {
        return Schedule_[i];
    }

private:
    Service::SeArray<RoundKey48, 16> Schedule_;

    static Key56 Pc1(Key64 key)
    {
        constexpr int_fast8_t PC1_TABLE[] =
        {
            57, 49, 41, 33, 25, 17,  9,
             1, 58, 50, 42, 34, 26, 18,
            10,  2, 59, 51, 43, 35, 27,
            19, 11,  3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
            14,  6, 61, 53, 45, 37, 29,
            21, 13,  5, 28, 20, 12,  4
        };

        static_assert(std::size(PC1_TABLE) == 56);

        return Bitwise::TableChoice<64, 56>(key,
                                            PC1_TABLE,
                                            PC1_TABLE + std::size(PC1_TABLE));
    }

    static RoundKey48 Pc2(Key56 key)
    {
        constexpr int_fast8_t PC2_TABLE[] =
        {
            14, 17, 11, 24,  1,  5,
             3, 28, 15,  6, 21, 10,
            23, 19, 12,  4, 26,  8,
            16,  7, 27, 20, 13,  2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

        static_assert(std::size(PC2_TABLE) == 48);

        return Bitwise::TableChoice<56, 48>(key,
                                            PC2_TABLE,
                                            PC2_TABLE + std::size(PC2_TABLE));
    }
};

} // namespace Chaos::Cipher::Des::Inner_

#endif // CHAOS_CIPHER_DES_DESCRYPT_HPP
