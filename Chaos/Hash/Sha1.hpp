#ifndef CHAOS_HASH_SHA1_HPP
#define CHAOS_HASH_SHA1_HPP

#include <cstdint>
#include <array>
#include <string>

#include "Hash.hpp"
#include "Hasher.hpp"

namespace Chaos::Hash::Sha1::Inner_
{

struct Buffer
{
    uint32_t Regs_[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
};

using Block = std::array<uint32_t, 16>;

struct Algorithm
{
public:
    static void UpdateBuffer(Buffer & buffer, const Block & block)
    {
        static_assert(std::tuple_size_v<ScheduledBlock> == 80);

        ScheduledBlock scheduled;
        ScheduleBlock(scheduled, block);

        uint32_t a = buffer.Regs_[0];
        uint32_t b = buffer.Regs_[1];
        uint32_t c = buffer.Regs_[2];
        uint32_t d = buffer.Regs_[3];
        uint32_t e = buffer.Regs_[4];

        for (int_fast8_t i = 0; i < 20; ++i)
        {
            PerformRound(a, b, c, d, e, F0, scheduled[i], 0x5a827999);
        }

        for (int_fast8_t i = 20; i < 40; ++i)
        {
            PerformRound(a, b, c, d, e, F20, scheduled[i], 0x6ed9eba1);
        }

        for (int_fast8_t i = 40; i < 60; ++i)
        {
            PerformRound(a, b, c, d, e, F40, scheduled[i], 0x8f1bbcdc);
        }

        for (int_fast8_t i = 60; i < 80; ++i)
        {
            PerformRound(a, b, c, d, e, F60, scheduled[i], 0xca62c1d6);
        }

        buffer.Regs_[0] += a;
        buffer.Regs_[1] += b;
        buffer.Regs_[2] += c;
        buffer.Regs_[3] += d;
        buffer.Regs_[4] += e;
    }

private:
    using ScheduledBlock = std::array<uint32_t, 80>;
    using RoundFunction = uint32_t (*)(uint32_t b, uint32_t c, uint32_t d);

    static uint32_t Rotl(uint32_t v, int_fast8_t s)
    {
        return (v << s) | (v >> (32 - s));
    }

    static uint32_t F0(uint32_t b, uint32_t c, uint32_t d)
    {
        return (b & c) | ((~b) & d);
    }

    static uint32_t F20(uint32_t b, uint32_t c, uint32_t d)
    {
        return b ^ c ^ d;
    }

    static uint32_t F40(uint32_t b, uint32_t c, uint32_t d)
    {
        return (b & c) | (b & d) | (c & d);
    }

    static uint32_t F60(uint32_t b, uint32_t c, uint32_t d)
    {
        return b ^ c ^ d;
    }

    static void ScheduleBlock(ScheduledBlock & result, const Block & block)
    {
        static_assert(std::tuple_size_v<Block> == 16);
        static_assert(std::tuple_size_v<ScheduledBlock> == 80);

        std::copy(block.begin(), block.end(), result.begin());

        for (int_fast8_t t = 16; t < 80; ++t)
        {
            result[t] = Rotl(result[t - 3] ^
                             result[t - 8] ^
                             result[t - 14] ^
                             result[t - 16], 1);
        }
    }

    static void PerformRound(uint32_t & a, uint32_t & b, uint32_t & c,
                             uint32_t & d, uint32_t & e,
                             RoundFunction func, uint32_t data, uint32_t k)
    {
        const uint32_t temp = Rotl(a, 5) + func(b, c, d) + e + data + k;

        e = d;
        d = c;
        c = Rotl(b, 30);
        b = a;
        a = temp;
    }
};

} // namespace Chaos::Hash::Sha1::Inner_

namespace Chaos::Hash::Sha1
{

struct Sha1Hash : public Hash<Sha1Hash>
{
    std::array<uint8_t, 20> GetRawDigest() const
    {
        return RawDigest_;
    }

    std::string ToHexString() const
    {
        char buf[41];

        std::sprintf(buf,
                     "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
                     "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                      RawDigest_[ 0], RawDigest_[ 1], RawDigest_[ 2], RawDigest_[ 3],
                      RawDigest_[ 4], RawDigest_[ 5], RawDigest_[ 6], RawDigest_[ 7],
                      RawDigest_[ 8], RawDigest_[ 9], RawDigest_[10], RawDigest_[11],
                      RawDigest_[12], RawDigest_[13], RawDigest_[14], RawDigest_[15],
                      RawDigest_[16], RawDigest_[17], RawDigest_[18], RawDigest_[19]);

        return std::string(buf, buf + 40);
    }

    std::array<uint8_t, 20> RawDigest_;
};

class Sha1Hasher : public Hasher<Sha1Hasher>
{
public:
    using HashType = Sha1Hash;

    static constexpr size_t BLOCK_SIZE_BYTES = 64;

    Sha1Hasher()
    {
        ResetImpl();
    }

    void Reset()
    {
        ResetImpl();
    }

    template<typename InputIt>
    void Update(InputIt begin, InputIt end)
    {
        MessageSizeBytes_ += UpdateImpl(begin, end);
    }

    HashType Finish()
    {
        uint64_t messageSizeBytesMod64 = MessageSizeBytes_ % 64;

        int_fast8_t paddingNeededBytes;

        if (messageSizeBytesMod64 < 56)
        {
            paddingNeededBytes = 56 - messageSizeBytesMod64;
        }
        else if (messageSizeBytesMod64 > 56)
        {
            paddingNeededBytes = 120 - messageSizeBytesMod64;
        }
        else
        {
            paddingNeededBytes = 64;
        }

        UpdateImpl(PAD_, PAD_ + paddingNeededBytes);

        const uint64_t messageSizeBits = MessageSizeBytes_ * 8;

        uint8_t encodedMessageSizeBits[] =
        {
            static_cast<uint8_t>((messageSizeBits >> 56) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >> 48) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >> 40) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >> 32) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >> 24) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >> 16) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >>  8) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >>  0) & 0xFF),
        };

        static_assert(std::size(encodedMessageSizeBits) == 8);

        UpdateImpl(encodedMessageSizeBits,
                   encodedMessageSizeBits + std::size(encodedMessageSizeBits));

        HashType result;

        int_fast8_t i = 0;
        for (int_fast8_t reg = 0; reg < 5; ++reg)
        {
            for (int_fast8_t shift = 0; shift < 32; shift += 8)
            {
                result.RawDigest_[i++] = (Buffer_.Regs_[reg] >> (24 - shift)) & 0xFF;
            }
        }

        return result;
    }

private:
    static constexpr uint8_t PAD_[] =
    {
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    static_assert(std::size(PAD_) == 64);

    Inner_::Buffer Buffer_;

    Inner_::Block Block_;
    int_fast8_t BlockSize_;

    uint32_t Word_;
    int_fast8_t WordBytesPacked_;

    uint64_t MessageSizeBytes_;

    void ResetImpl()
    {
        Buffer_ = Inner_::Buffer();
        Block_.fill(0);

        BlockSize_ = 0;
        Word_ = 0;
        WordBytesPacked_ = 0;
        MessageSizeBytes_ = 0;
    }

    template<typename InputIt>
    uint64_t UpdateImpl(InputIt begin, InputIt end)
    {
        uint64_t written = 0;

        for (InputIt it = begin; it != end; ++it, ++written)
        {
            Word_ |= (static_cast<uint32_t>(*it) << (24 - (WordBytesPacked_ * 8)));
            ++WordBytesPacked_;

            if (WordBytesPacked_ == 4)
            {
                Block_[BlockSize_++] = Word_;
                WordBytesPacked_ = 0;
                Word_ = 0;

                if (BlockSize_ == 16)
                {
                    Inner_::Algorithm::UpdateBuffer(Buffer_, Block_);
                    BlockSize_ = 0;
                }
            }
        }

        return written;
    }
};

} // namespace Chaos::Hash::Sha1

#endif // CHAOS_HASH_SHA1_HPP
