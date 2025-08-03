#ifndef CHAOS_MD5HASHER_HPP
#define CHAOS_MD5HASHER_HPP

#include <cstdint>
#include <array>
#include <string>

namespace Chaos::Md5
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

        FF(a, b, c, d, block[ 0], 0xd76aa478,  7);
        FF(d, a, b, c, block[ 1], 0xe8c7b756, 12);
        FF(c, d, a, b, block[ 2], 0x242070db, 17);
        FF(b, c, d, a, block[ 3], 0xc1bdceee, 22);
        FF(a, b, c, d, block[ 4], 0xf57c0faf,  7);
        FF(d, a, b, c, block[ 5], 0x4787c62a, 12);
        FF(c, d, a, b, block[ 6], 0xa8304613, 17);
        FF(b, c, d, a, block[ 7], 0xfd469501, 22);
        FF(a, b, c, d, block[ 8], 0x698098d8,  7);
        FF(d, a, b, c, block[ 9], 0x8b44f7af, 12);
        FF(c, d, a, b, block[10], 0xffff5bb1, 17);
        FF(b, c, d, a, block[11], 0x895cd7be, 22);
        FF(a, b, c, d, block[12], 0x6b901122,  7);
        FF(d, a, b, c, block[13], 0xfd987193, 12);
        FF(c, d, a, b, block[14], 0xa679438e, 17);
        FF(b, c, d, a, block[15], 0x49b40821, 22);

        GG(a, b, c, d, block[ 1], 0xf61e2562,  5);
        GG(d, a, b, c, block[ 6], 0xc040b340,  9);
        GG(c, d, a, b, block[11], 0x265e5a51, 14);
        GG(b, c, d, a, block[ 0], 0xe9b6c7aa, 20);
        GG(a, b, c, d, block[ 5], 0xd62f105d,  5);
        GG(d, a, b, c, block[10], 0x02441453,  9);
        GG(c, d, a, b, block[15], 0xd8a1e681, 14);
        GG(b, c, d, a, block[ 4], 0xe7d3fbc8, 20);
        GG(a, b, c, d, block[ 9], 0x21e1cde6,  5);
        GG(d, a, b, c, block[14], 0xc33707d6,  9);
        GG(c, d, a, b, block[ 3], 0xf4d50d87, 14);
        GG(b, c, d, a, block[ 8], 0x455a14ed, 20);
        GG(a, b, c, d, block[13], 0xa9e3e905,  5);
        GG(d, a, b, c, block[ 2], 0xfcefa3f8,  9);
        GG(c, d, a, b, block[ 7], 0x676f02d9, 14);
        GG(b, c, d, a, block[12], 0x8d2a4c8a, 20);

        HH(a, b, c, d, block[ 5], 0xfffa3942,  4);
        HH(d, a, b, c, block[ 8], 0x8771f681, 11);
        HH(c, d, a, b, block[11], 0x6d9d6122, 16);
        HH(b, c, d, a, block[14], 0xfde5380c, 23);
        HH(a, b, c, d, block[ 1], 0xa4beea44,  4);
        HH(d, a, b, c, block[ 4], 0x4bdecfa9, 11);
        HH(c, d, a, b, block[ 7], 0xf6bb4b60, 16);
        HH(b, c, d, a, block[10], 0xbebfbc70, 23);
        HH(a, b, c, d, block[13], 0x289b7ec6,  4);
        HH(d, a, b, c, block[ 0], 0xeaa127fa, 11);
        HH(c, d, a, b, block[ 3], 0xd4ef3085, 16);
        HH(b, c, d, a, block[ 6], 0x04881d05, 23);
        HH(a, b, c, d, block[ 9], 0xd9d4d039,  4);
        HH(d, a, b, c, block[12], 0xe6db99e5, 11);
        HH(c, d, a, b, block[15], 0x1fa27cf8, 16);
        HH(b, c, d, a, block[ 2], 0xc4ac5665, 23);

        II(a, b, c, d, block[ 0], 0xf4292244,  6);
        II(d, a, b, c, block[ 7], 0x432aff97, 10);
        II(c, d, a, b, block[14], 0xab9423a7, 15);
        II(b, c, d, a, block[ 5], 0xfc93a039, 21);
        II(a, b, c, d, block[12], 0x655b59c3,  6);
        II(d, a, b, c, block[ 3], 0x8f0ccc92, 10);
        II(c, d, a, b, block[10], 0xffeff47d, 15);
        II(b, c, d, a, block[ 1], 0x85845dd1, 21);
        II(a, b, c, d, block[ 8], 0x6fa87e4f,  6);
        II(d, a, b, c, block[15], 0xfe2ce6e0, 10);
        II(c, d, a, b, block[ 6], 0xa3014314, 15);
        II(b, c, d, a, block[13], 0x4e0811a1, 21);
        II(a, b, c, d, block[ 4], 0xf7537e82,  6);
        II(d, a, b, c, block[11], 0xbd3af235, 10);
        II(c, d, a, b, block[ 2], 0x2ad7d2bb, 15);
        II(b, c, d, a, block[ 9], 0xeb86d391, 21);

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
        return (x & z) | (y & (~z));
    }

    static uint32_t H(uint32_t x, uint32_t y, uint32_t z)
    {
        return x ^ y ^ z;
    }

    static uint32_t I(uint32_t x, uint32_t y, uint32_t z)
    {
        return y ^ (x | (~z));
    }

    static void FF(uint32_t & a, uint32_t b, uint32_t c, uint32_t d,
                   uint32_t x, uint32_t t, int_fast8_t s)
    {
        a = b + Rotl(a + F(b, c, d) + x + t, s);
    }

    static void GG(uint32_t & a, uint32_t b, uint32_t c, uint32_t d,
                   uint32_t x, uint32_t t, int_fast8_t s)
    {
        a = b + Rotl(a + G(b, c, d) + x + t, s);
    }

    static void HH(uint32_t & a, uint32_t b, uint32_t c, uint32_t d,
                   uint32_t x, uint32_t t, int_fast8_t s)
    {
        a = b + Rotl(a + H(b, c, d) + x + t, s);
    }

    static void II(uint32_t & a, uint32_t b, uint32_t c, uint32_t d,
                   uint32_t x, uint32_t t, int_fast8_t s)
    {
        a = b + Rotl(a + I(b, c, d) + x + t, s);
    }
};

struct Hash
{
    std::string ToHexString() const
    {
        char buf[33];

        std::sprintf(buf,
                     "%02x%02x%02x%02x%02x%02x%02x%02x"
                     "%02x%02x%02x%02x%02x%02x%02x%02x",
                      RawDigest[ 0], RawDigest[ 1], RawDigest[ 2], RawDigest[ 3],
                      RawDigest[ 4], RawDigest[ 5], RawDigest[ 6], RawDigest[ 7],
                      RawDigest[ 8], RawDigest[ 9], RawDigest[10], RawDigest[11],
                      RawDigest[12], RawDigest[13], RawDigest[14], RawDigest[15]);

        return std::string(buf, buf + 32);
    }

    std::array<uint8_t, 16> RawDigest;
};

class Hasher
{
public:
    Hasher()
        : BlockSize_(0)
        , Word_(0)
        , WordBytesPacked_(0)
        , MessageSizeBytes_(0)
    {
        Block_.fill(0);
    }

    template<typename InputIt>
    void Update(InputIt begin, InputIt end)
    {
        MessageSizeBytes_ += UpdateImpl(begin, end);
    }

    Hash Finish()
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

        Hash result;

        int_fast8_t i = 0;
        for (int_fast8_t reg = 0; reg < 4; ++reg)
        {
            for (int_fast8_t shift = 0; shift < 32; shift += 8)
            {
                result.RawDigest[i++] = (Buffer_.Regs_[reg] >> shift) & 0xFF;
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

    Buffer Buffer_;

    Block Block_;
    int_fast8_t BlockSize_;

    uint32_t Word_;
    int_fast8_t WordBytesPacked_;

    uint64_t MessageSizeBytes_;

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
                    Algorithm::UpdateBuffer(Buffer_, Block_);
                    BlockSize_ = 0;
                }
            }
        }

        return written;
    }
};

} // namespace Chaos::Md5

#endif
