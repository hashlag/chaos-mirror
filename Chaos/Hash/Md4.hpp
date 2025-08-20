#ifndef CHAOS_HASH_MD4HASHER_HPP
#define CHAOS_HASH_MD4HASHER_HPP

#include <cstdint>
#include <array>
#include <string>

#include "Hash.hpp"
#include "Hasher.hpp"

namespace Chaos::Hash::Md4::Inner_
{

struct Buffer
{
    uint32_t Regs_[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
};

using Block = std::array<uint32_t, 16>;

struct Algorithm
{
public:
    static void UpdateBuffer(Buffer & buffer, const Block & block)
    {
        uint32_t a = buffer.Regs_[0];
        uint32_t b = buffer.Regs_[1];
        uint32_t c = buffer.Regs_[2];
        uint32_t d = buffer.Regs_[3];

        FF(a, b, c, d, block[ 0],  3);
        FF(d, a, b, c, block[ 1],  7);
        FF(c, d, a, b, block[ 2], 11);
        FF(b, c, d, a, block[ 3], 19);
        FF(a, b, c, d, block[ 4],  3);
        FF(d, a, b, c, block[ 5],  7);
        FF(c, d, a, b, block[ 6], 11);
        FF(b, c, d, a, block[ 7], 19);
        FF(a, b, c, d, block[ 8],  3);
        FF(d, a, b, c, block[ 9],  7);
        FF(c, d, a, b, block[10], 11);
        FF(b, c, d, a, block[11], 19);
        FF(a, b, c, d, block[12],  3);
        FF(d, a, b, c, block[13],  7);
        FF(c, d, a, b, block[14], 11);
        FF(b, c, d, a, block[15], 19);

        GG(a, b, c, d, block[ 0],  3);
        GG(d, a, b, c, block[ 4],  5);
        GG(c, d, a, b, block[ 8],  9);
        GG(b, c, d, a, block[12], 13);
        GG(a, b, c, d, block[ 1],  3);
        GG(d, a, b, c, block[ 5],  5);
        GG(c, d, a, b, block[ 9],  9);
        GG(b, c, d, a, block[13], 13);
        GG(a, b, c, d, block[ 2],  3);
        GG(d, a, b, c, block[ 6],  5);
        GG(c, d, a, b, block[10],  9);
        GG(b, c, d, a, block[14], 13);
        GG(a, b, c, d, block[ 3],  3);
        GG(d, a, b, c, block[ 7],  5);
        GG(c, d, a, b, block[11],  9);
        GG(b, c, d, a, block[15], 13);

        HH(a, b, c, d, block[ 0],  3);
        HH(d, a, b, c, block[ 8],  9);
        HH(c, d, a, b, block[ 4], 11);
        HH(b, c, d, a, block[12], 15);
        HH(a, b, c, d, block[ 2],  3);
        HH(d, a, b, c, block[10],  9);
        HH(c, d, a, b, block[ 6], 11);
        HH(b, c, d, a, block[14], 15);
        HH(a, b, c, d, block[ 1],  3);
        HH(d, a, b, c, block[ 9],  9);
        HH(c, d, a, b, block[ 5], 11);
        HH(b, c, d, a, block[13], 15);
        HH(a, b, c, d, block[ 3],  3);
        HH(d, a, b, c, block[11],  9);
        HH(c, d, a, b, block[ 7], 11);
        HH(b, c, d, a, block[15], 15);

        buffer.Regs_[0] += a;
        buffer.Regs_[1] += b;
        buffer.Regs_[2] += c;
        buffer.Regs_[3] += d;
    }

private:
    static uint32_t Rotl(uint32_t v, int_fast8_t s)
    {
        return (v << s) | (v >> (32 - s));
    }

    static uint32_t F(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) | ((~x) & z);
    }

    static uint32_t G(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) | (x & z) | (y & z);
    }

    static uint32_t H(uint32_t x, uint32_t y, uint32_t z)
    {
        return x ^ y ^ z;
    }

    static void FF(uint32_t & a, uint32_t b, uint32_t c, uint32_t d,
                   uint32_t x, int_fast8_t s)
    {
        a = Rotl(a + F(b, c, d) + x, s);
    }

    static void GG(uint32_t & a, uint32_t b, uint32_t c, uint32_t d,
                   uint32_t x, int_fast8_t s)
    {
        constexpr uint32_t C2 = 0x5a827999;

        a = Rotl(a + G(b, c, d) + x + C2, s);
    }

    static void HH(uint32_t & a, uint32_t b, uint32_t c, uint32_t d,
                   uint32_t x, int_fast8_t s)
    {
        constexpr uint32_t C3 = 0x6ed9eba1;

        a = Rotl(a + H(b, c, d) + x + C3, s);
    }
};

} // namespace Chaos::Hash::Md4::Inner_

namespace Chaos::Hash::Md4
{

struct Md4Hash : public Hash<Md4Hash>
{
    std::array<uint8_t, 16> GetRawDigest() const
    {
        return RawDigest_;
    }

    std::string ToHexString() const
    {
        char buf[33];

        std::sprintf(buf,
                     "%02x%02x%02x%02x%02x%02x%02x%02x"
                     "%02x%02x%02x%02x%02x%02x%02x%02x",
                      RawDigest_[ 0], RawDigest_[ 1], RawDigest_[ 2], RawDigest_[ 3],
                      RawDigest_[ 4], RawDigest_[ 5], RawDigest_[ 6], RawDigest_[ 7],
                      RawDigest_[ 8], RawDigest_[ 9], RawDigest_[10], RawDigest_[11],
                      RawDigest_[12], RawDigest_[13], RawDigest_[14], RawDigest_[15]);

        return std::string(buf, buf + 32);
    }

    std::array<uint8_t, 16> RawDigest_;
};

class Md4Hasher : public Hasher<Md4Hasher>
{
public:
    using HashType = Md4Hash;

    static constexpr size_t BLOCK_SIZE_BYTES = 64;

    Md4Hasher()
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
            static_cast<uint8_t>((messageSizeBits >>  0) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >>  8) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >> 16) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >> 24) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >> 32) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >> 40) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >> 48) & 0xFF),
            static_cast<uint8_t>((messageSizeBits >> 56) & 0xFF),
        };

        static_assert(std::size(encodedMessageSizeBits) == 8);

        UpdateImpl(encodedMessageSizeBits,
                   encodedMessageSizeBits + std::size(encodedMessageSizeBits));

        HashType result;

        int_fast8_t i = 0;
        for (int_fast8_t reg = 0; reg < 4; ++reg)
        {
            for (int_fast8_t shift = 0; shift < 32; shift += 8)
            {
                result.RawDigest_[i++] = (Buffer_.Regs_[reg] >> shift) & 0xFF;
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
            Word_ |= (static_cast<uint32_t>(*it) << (WordBytesPacked_ * 8));
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

} // namespace Chaos::Hash::Md4

#endif
