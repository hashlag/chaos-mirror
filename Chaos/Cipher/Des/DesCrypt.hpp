#ifndef CHAOS_CIPHER_DES_DESCRYPT_HPP
#define CHAOS_CIPHER_DES_DESCRYPT_HPP

#include <algorithm>
#include <utility>

#include "Service/ChaosException.hpp"
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

    template<typename OutputIt>
    static void CrunchUInt64(OutputIt out, uint64_t value)
    {
        for (int_fast8_t i = 0; i < 8; ++i)
        {
            *out++ = (value >> (56 - (i * 8))) & Mask<8>();
        }
    }
};

using RawKey = Service::SeArray<uint8_t, 8>;

class KeySchedule
{
public:
    using Key64 = uint64_t;
    using Key56 = uint64_t;

    using RoundKey48 = uint64_t;

    enum class Direction
    {
        Encrypt,
        Decrypt
    };

    KeySchedule(Direction direction, const RawKey & rawKey)
    {
        Key56 key56 = Pc1(Bitwise::PackUInt64(rawKey.Begin(), rawKey.End()));

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

        if (direction == Direction::Decrypt)
        {
            std::reverse(Schedule_.Begin(), Schedule_.End());
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

namespace Chaos::Cipher::Des
{

class DesCrypt
{
public:
    DesCrypt() = delete;

    class Key
    {
        friend class DesCrypt;
    public:
        template<typename InputIt>
        Key(InputIt keyBegin, InputIt keyEnd)
        {
            int_fast8_t i = 0;
            InputIt keyIt = keyBegin;
            for (; i < Key_.Size() && keyIt != keyEnd; ++i, ++keyIt)
            {
                Key_[i] = *keyIt;
            }

            if (i != Key_.Size() || keyIt != keyEnd)
            {
                throw Service::ChaosException("DesCrypt::Key: invalid key length "
                                              "(8 bytes required)");
            }
        }

    private:
        Inner_::RawKey Key_;
    };

    class Encryptor
    {
    public:
        Encryptor(const Key & key)
            : Schedule_(Inner_::KeySchedule::Direction::Encrypt, key.Key_)
        { }

        template<typename OutputIt, typename InputIt>
        void EncryptBlock(OutputIt out, InputIt inBegin, InputIt inEnd)
        {
            RawBlockArray block;

            int_fast8_t i = 0;
            for (InputIt in = inBegin; i < block.Size() && in != inEnd; ++i, ++in)
            {
                block[i] = *in;
            }

            Block encrypted
                = DesCrypt::ProcessBlock(Inner_::Bitwise::PackUInt64(block.Begin(),
                                                                     block.End()),
                                         Schedule_);

            Inner_::Bitwise::CrunchUInt64(out, encrypted);
        }

        uint64_t EncryptBlock(uint64_t block)
        {
            return DesCrypt::ProcessBlock(block, Schedule_);
        }

    private:
        Inner_::KeySchedule Schedule_;
    };

    class Decryptor
    {
    public:
        Decryptor(const Key & key)
            : Schedule_(Inner_::KeySchedule::Direction::Decrypt, key.Key_)
        { }

        template<typename OutputIt, typename InputIt>
        void DecryptBlock(OutputIt out, InputIt inBegin, InputIt inEnd)
        {
            RawBlockArray block;

            int_fast8_t i = 0;
            for (InputIt in = inBegin; i < block.Size() && in != inEnd; ++i, ++in)
            {
                block[i] = *in;
            }

            Block decrypted
                = DesCrypt::ProcessBlock(Inner_::Bitwise::PackUInt64(block.Begin(),
                                                                     block.End()),
                                         Schedule_);

            Inner_::Bitwise::CrunchUInt64(out, decrypted);
        }

    private:
        Inner_::KeySchedule Schedule_;
    };

private:
    using Block = uint64_t;
    using BlockHalf = uint32_t;
    using RawBlockArray = Service::SeArray<uint8_t, 8>;
    using Data48 = uint64_t;
    using Data32 = uint32_t;
    using Data6 = uint8_t;
    using Data4 = uint8_t;

    static Data48 E(Data32 value)
    {
        constexpr int_fast8_t E_TABLE[] =
        {
            32,  1,  2,  3,  4,  5,
             4,  5,  6,  7,  8,  9,
             8,  9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1
        };

        static_assert(std::size(E_TABLE) == 48);

        return Inner_::Bitwise::TableChoice<32, 48>(value,
                                                    E_TABLE,
                                                    E_TABLE + std::size(E_TABLE));
    }

    static Data32 SBlock(Data48 value)
    {
        constexpr Data4 SBOX_TABLES[][64] =
        {
            {
                14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
                 3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
                 4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
                15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13
            },
            {
                15,  3,  1, 13,  8,  4, 14,  7,  6, 15, 11,  2,  3,  8,  4, 14,
                 9, 12,  7,  0,  2,  1, 13, 10, 12,  6,  0,  9,  5, 11, 10,  5,
                 0, 13, 14,  8,  7, 10, 11,  1, 10,  3,  4, 15, 13,  4,  1,  2,
                 5, 11,  8,  6, 12,  7,  6, 12,  9,  0,  3,  5,  2, 14, 15,  9
            },
            {
                10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
                 1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
                13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
                11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12
            },
            {
                 7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
                 1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
                10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
                15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14
            },
            {
                 2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
                 8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
                 4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
                15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3
            },
            {
                12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
                 0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
                 9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
                 7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13
            },
            {
                 4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
                 3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
                 1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
                10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12
            },
            {
                13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
                10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
                 7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
                 0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11
            }
        };

        static_assert(std::size(SBOX_TABLES) == 8);

        Data32 result = 0;

        for (int_fast8_t i = 0; i < 8; ++i)
        {
            Data6 input = (value >> (42 - (i * 6))) & Inner_::Bitwise::Mask<6>();
            result |= static_cast<Data32>(SBOX_TABLES[i][input]) << (28 - (i * 4));
        }

        return result;
    }

    static Data32 P(Data32 value)
    {
        constexpr int_fast8_t P_TABLE[] =
        {
            16,  7, 20, 21,
            29, 12, 28, 17,
             1, 15, 23, 26,
             5, 18, 31, 10,
             2,  8, 24, 14,
            32, 27,  3,  9,
            19, 13, 30,  6,
            22, 11,  4, 25
        };

        static_assert(std::size(P_TABLE) == 32);

        return Inner_::Bitwise::TableChoice<32, 32>(value,
                                                    P_TABLE,
                                                    P_TABLE + std::size(P_TABLE));
    }

    static BlockHalf F(BlockHalf value, Inner_::KeySchedule::RoundKey48 roundKey)
    {
        Data48 expanded = E(value);
        expanded = (expanded ^ roundKey) & Inner_::Bitwise::Mask<48>();

        return P(SBlock(expanded));
    }

    static Block Ip(Block block)
    {
        constexpr int_fast8_t IP_TABLE[] =
        {
            58, 50, 42, 34, 26, 18, 10,  2,
            60, 52, 44, 36, 28, 20, 12,  4,
            62, 54, 46, 38, 30, 22, 14,  6,
            64, 56, 48, 40, 32, 24, 16,  8,
            57, 49, 41, 33, 25, 17,  9,  1,
            59, 51, 43, 35, 27, 19, 11,  3,
            61, 53, 45, 37, 29, 21, 13,  5,
            63, 55, 47, 39, 31, 23, 15,  7
        };

        static_assert(std::size(IP_TABLE) == 64);

        return Inner_::Bitwise::TableChoice<64, 64>(block,
                                                    IP_TABLE,
                                                    IP_TABLE + std::size(IP_TABLE));
    }

    static Block Fp(Block block)
    {
        constexpr int_fast8_t FP_TABLE[] =
        {
            40,  8, 48, 16, 56, 24, 64, 32,
            39,  7, 47, 15, 55, 23, 63, 31,
            38,  6, 46, 14, 54, 22, 62, 30,
            37,  5, 45, 13, 53, 21, 61, 29,
            36,  4, 44, 12, 52, 20, 60, 28,
            35,  3, 43, 11, 51, 19, 59, 27,
            34,  2, 42, 10, 50, 18, 58, 26,
            33,  1, 41,  9, 49, 17, 57, 25
        };

        static_assert(std::size(FP_TABLE) == 64);

        return Inner_::Bitwise::TableChoice<64, 64>(block,
                                                    FP_TABLE,
                                                    FP_TABLE + std::size(FP_TABLE));
    }

    static Block ProcessBlock(Block block, const Inner_::KeySchedule & schedule)
    {
        block = Ip(block);

        uint32_t l32;
        uint32_t r32;

        {
            auto [l, r] = Inner_::Bitwise::Split<32>(block);
            l32 = static_cast<uint32_t>(l);
            r32 = static_cast<uint32_t>(r);
        }

        for (int_fast8_t i = 0; i < 16; ++i)
        {
            uint32_t l32Old = l32;

            l32 = r32;
            r32 = l32Old ^ F(r32, schedule[i]);
        }

        return Fp(Inner_::Bitwise::Merge<32>(r32, l32));
    }
};

} // namespace Chaos::Cipher::Des

#endif // CHAOS_CIPHER_DES_DESCRYPT_HPP
