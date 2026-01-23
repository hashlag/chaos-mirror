#include <gtest/gtest.h>

#include "Cipher/Des/DesCrypt.hpp"

using namespace Chaos::Cipher::Des;

TEST(DesCryptTests, KeyScheduleTest)
{
    Inner_::RawKey key;

    key[0] = 0b00010011;
    key[1] = 0b00110100;
    key[2] = 0b01010111;
    key[3] = 0b01111001;
    key[4] = 0b10011011;
    key[5] = 0b10111100;
    key[6] = 0b11011111;
    key[7] = 0b11110001;

    Inner_::KeySchedule schedule(key);

    ASSERT_EQ(0b000110110000001011101111111111000111000001110010ULL, schedule[0]);
    ASSERT_EQ(0b011110011010111011011001110110111100100111100101ULL, schedule[1]);
    ASSERT_EQ(0b010101011111110010001010010000101100111110011001ULL, schedule[2]);
    ASSERT_EQ(0b011100101010110111010110110110110011010100011101ULL, schedule[3]);
    ASSERT_EQ(0b011111001110110000000111111010110101001110101000ULL, schedule[4]);
    ASSERT_EQ(0b011000111010010100111110010100000111101100101111ULL, schedule[5]);
    ASSERT_EQ(0b111011001000010010110111111101100001100010111100ULL, schedule[6]);
    ASSERT_EQ(0b111101111000101000111010110000010011101111111011ULL, schedule[7]);
    ASSERT_EQ(0b111000001101101111101011111011011110011110000001ULL, schedule[8]);
    ASSERT_EQ(0b101100011111001101000111101110100100011001001111ULL, schedule[9]);
    ASSERT_EQ(0b001000010101111111010011110111101101001110000110ULL, schedule[10]);
    ASSERT_EQ(0b011101010111000111110101100101000110011111101001ULL, schedule[11]);
    ASSERT_EQ(0b100101111100010111010001111110101011101001000001ULL, schedule[12]);
    ASSERT_EQ(0b010111110100001110110111111100101110011100111010ULL, schedule[13]);
    ASSERT_EQ(0b101111111001000110001101001111010011111100001010ULL, schedule[14]);
    ASSERT_EQ(0b110010110011110110001011000011100001011111110101ULL, schedule[15]);
}

TEST(DesCryptTests, EncryptTest)
{
    struct Helper
    {
        std::array<uint8_t, 8> operator()(const std::array<uint8_t, 8> & data,
                                          const std::array<uint8_t, 8> & key) const
        {
            std::array<uint8_t, 8> result;
            result.fill(0);

            DesCrypt::Key desKey(key.begin(), key.end());
            DesCrypt::Encryptor enc(desKey);
            enc.EncryptBlock(result.begin(), data.begin(), data.end());

            return result;
        }
    };

    Helper des;

    {
        std::array<uint8_t, 8> data = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
        std::array<uint8_t, 8> key = { 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 };

        std::array<uint8_t, 8> expected = { 0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05 };

        ASSERT_EQ(expected, des(data, key));
    }

    {
        std::array<uint8_t, 8> data = { 0xaa, 0xf3, 0x83, 0x16, 0x2d, 0x2e, 0x6b, 0xcb };
        std::array<uint8_t, 8> key = { 0x44, 0xbf, 0x32, 0x19, 0x99, 0x25, 0x81, 0x51 };

        std::array<uint8_t, 8> expected = { 0x07, 0xe8, 0x7f, 0xaa, 0xb3, 0x17, 0x13, 0x18 };

        ASSERT_EQ(expected, des(data, key));
    }

    {
        std::array<uint8_t, 8> data = { 0xe5, 0x1a, 0x9f, 0xd4, 0x19, 0xa7, 0x93, 0x44 };
        std::array<uint8_t, 8> key = { 0xda, 0xec, 0x68, 0xae, 0x83, 0xe0, 0x1e, 0xab };

        std::array<uint8_t, 8> expected = { 0x42, 0x27, 0x88, 0xa6, 0x7b, 0x6c, 0x18, 0xed };

        ASSERT_EQ(expected, des(data, key));
    }
}

TEST(DesCryptTests, EncryptShortDataTest)
{
    struct Helper
    {
        std::vector<uint8_t> operator()(const std::vector<uint8_t> & data,
                                        const std::vector<uint8_t> & key)
        {
            std::vector<uint8_t> result;
            result.resize(8, 0);

            DesCrypt::Key desKey(key.begin(), key.end());
            DesCrypt::Encryptor enc(desKey);
            enc.EncryptBlock(result.begin(), data.begin(), data.end());

            return result;
        }
    };

    Helper des;

    {
        // treated as { 0xe5, 0x1a, 0x9f, 0xd4, 0x19, 0x00, 0x00, 0x00 }
        std::vector<uint8_t> dataShort = { 0xe5, 0x1a, 0x9f, 0xd4, 0x19 };

        std::vector<uint8_t> data = { 0xe5, 0x1a, 0x9f, 0xd4, 0x19, 0x00, 0x00, 0x00 };
        std::vector<uint8_t> key = { 0xda, 0xec, 0x68, 0xae, 0x83, 0xe0, 0x1e, 0xab };

        std::vector<uint8_t> expected = { 0xd8, 0xa8, 0xb8, 0xb4, 0xc0, 0x9b, 0x04, 0x09 };

        ASSERT_EQ(expected, des(data, key));
        ASSERT_EQ(expected, des(dataShort, key));
    }
}

TEST(DesCryptTests, EncryptLongDataTest)
{
    struct Helper
    {
        std::vector<uint8_t> operator()(const std::vector<uint8_t> & data,
                                        const std::vector<uint8_t> & key)
        {
            std::vector<uint8_t> result;
            result.resize(8, 0);

            DesCrypt::Key desKey(key.begin(), key.end());
            DesCrypt::Encryptor enc(desKey);
            enc.EncryptBlock(result.begin(), data.begin(), data.end());

            return result;
        }
    };

    Helper des;

    {
        // treated as { 0xe5, 0x1a, 0x9f, 0xd4, 0x19, 0xa7, 0x93, 0x44 }
        std::vector<uint8_t> dataLong = { 0xe5, 0x1a, 0x9f, 0xd4, 0x19, 0xa7, 0x93, 0x44, 0xaa, 0xbb };

        std::vector<uint8_t> data = { 0xe5, 0x1a, 0x9f, 0xd4, 0x19, 0xa7, 0x93, 0x44 };
        std::vector<uint8_t> key = { 0xda, 0xec, 0x68, 0xae, 0x83, 0xe0, 0x1e, 0xab };

        std::vector<uint8_t> expected = { 0x42, 0x27, 0x88, 0xa6, 0x7b, 0x6c, 0x18, 0xed };

        ASSERT_EQ(expected, des(data, key));
        ASSERT_EQ(expected, des(dataLong, key));
    }
}

TEST(DesCryptTests, ShortKeyTest)
{
    {
        std::array<uint8_t, 7> key = {};
        ASSERT_THROW(DesCrypt::Key(key.begin(), key.end()), Chaos::Service::ChaosException);
    }
}

TEST(DesCryptTests, LongKeyTest)
{
    {
        std::array<uint8_t, 9> key = {};
        ASSERT_THROW(DesCrypt::Key(key.begin(), key.end()), Chaos::Service::ChaosException);
    }
}

TEST(DesCryptTests, OutIteratorUsageTest)
{
    struct OutputItMock
    {
        OutputItMock(size_t & asteriskCalls, size_t & incrementCalls)
            : AsteriskCalls_(asteriskCalls)
            , IncrementCalls_(incrementCalls)
        { }

        uint8_t & operator*()
        {
            ++AsteriskCalls_;

            static uint8_t dummy = 0;
            return dummy;
        }

        OutputItMock operator++(int)
        {
            ++IncrementCalls_;

            return *this;
        }

        size_t & AsteriskCalls_;
        size_t & IncrementCalls_;
    };

    {
        std::array<uint8_t, 8> data = { 0xe5, 0x1a, 0x9f, 0xd4, 0x19, 0xa7, 0x93, 0x44 };
        std::array<uint8_t, 8> key = { 0xda, 0xec, 0x68, 0xae, 0x83, 0xe0, 0x1e, 0xab };

        size_t asteriskCalls = 0;
        size_t incrementCalls = 0;
        OutputItMock it(asteriskCalls, incrementCalls);

        DesCrypt::Key desKey(key.begin(), key.end());
        DesCrypt::Encryptor enc(desKey);
        enc.EncryptBlock(it, data.begin(), data.end());

        ASSERT_EQ(8, asteriskCalls);
        ASSERT_EQ(8, incrementCalls);
    }

    {
        std::array<uint8_t, 11> data = { 0xe5, 0x1a, 0x9f, 0xd4, 0x19, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f, 0x9f };
        std::array<uint8_t, 8> key = { 0xda, 0xec, 0x68, 0xae, 0x83, 0xe0, 0x1e, 0xab };

        size_t asteriskCalls = 0;
        size_t incrementCalls = 0;
        OutputItMock it(asteriskCalls, incrementCalls);

        DesCrypt::Key desKey(key.begin(), key.end());
        DesCrypt::Encryptor enc(desKey);
        enc.EncryptBlock(it, data.begin(), data.end());

        ASSERT_EQ(8, asteriskCalls);
        ASSERT_EQ(8, incrementCalls);
    }
}
