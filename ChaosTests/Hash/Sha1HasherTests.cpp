#include <gtest/gtest.h>

#include "Hash/Sha1.hpp"

using namespace Chaos::Hash::Sha1;

TEST(Sha1Tests, RfcTest)
{
    struct Helper
    {
        std::string operator()(const char * in) const
        {
            Sha1Hasher hasher;
            hasher.Update(in, in + strlen(in));
            return hasher.Finish().ToHexString();
        }
    };

    Helper hash;

    ASSERT_EQ("da39a3ee5e6b4b0d3255bfef95601890afd80709", hash(""));
    ASSERT_EQ("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", hash("a"));
    ASSERT_EQ("a9993e364706816aba3e25717850c26c9cd0d89d", hash("abc"));
    ASSERT_EQ("84983e441c3bd26ebaae4aa1f95129e5e54670f1", hash("abcdbcdecdefdefgefghfghighijhi"
                                                               "jkijkljklmklmnlmnomnopnopq"));
    ASSERT_EQ("e0c094e867ef46c350ef54a7f59dd60bed92ae83", hash("01234567012345670123456701234567"
                                                               "01234567012345670123456701234567"));
}

TEST(Sha1Tests, PartialUpdateTest)
{
    {
        // "a"
        Sha1Hasher hasher;

        {
            const char * in = "a";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "";
            hasher.Update(in, in + strlen(in));
        }

        ASSERT_EQ("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", hasher.Finish().ToHexString());
    }

    {
        // "abc"
        Sha1Hasher hasher;

        {
            const char * in = "ab";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "c";
            hasher.Update(in, in + strlen(in));
        }

        ASSERT_EQ("a9993e364706816aba3e25717850c26c9cd0d89d", hasher.Finish().ToHexString());
    }

    {
        // "message digest"
        Sha1Hasher hasher;

        {
            const char * in = "me";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "ssage ";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "diges";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "t";
            hasher.Update(in, in + strlen(in));
        }

        ASSERT_EQ("c12252ceda8be8994d5fa0290a47231c1d16aae3", hasher.Finish().ToHexString());
    }

    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        Sha1Hasher hasher;

        {
            const char * in = "12345678901234567890";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "12345678901234567890";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "12345678901234567890";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "12345678901234567890";
            hasher.Update(in, in + strlen(in));
        }

        ASSERT_EQ("50abf5706a150990a08b2c5ea40fa0e585554732", hasher.Finish().ToHexString());
    }

    {
        // > 56 (mod 64) bytes.
        // "01234567012345670123456701234567012345670123456701234567012"
        Sha1Hasher hasher;

        {
            const char * in = "0123456701234567012345670";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "1234567012345670123456701234567012";
            hasher.Update(in, in + strlen(in));
        }

        ASSERT_EQ("48a2aded798429970468e8aa77bdc1840dbca3fe", hasher.Finish().ToHexString());
    }
}

TEST(Sha1Tests, LongInputTest)
{
    struct Helper
    {
        std::string operator()(const char * in) const
        {
            Sha1Hasher hasher;
            hasher.Update(in, in + strlen(in));
            return hasher.Finish().ToHexString();
        }
    };

    Helper hash;

    // 2500 zeros ('0').
    ASSERT_EQ("79e7958997241a7ffe484e14cbe1a41a088aa70b", hash(std::string(2500, '0').c_str()));
    // 1000 'a' followed by 1000 'b'.
    ASSERT_EQ("246f7ca16d5edebf7a5df7ddeab7c044745942ec", hash((std::string(1000, 'a') +
                                                                std::string(1000, 'b')).c_str()));
}

TEST(Sha1Tests, LongInputPartialUpdateTest)
{
    {
        // 2500 zeros ('0').
        Sha1Hasher hasher;

        std::string in(750, '0');

        hasher.Update(in.begin(), in.begin() + 250);
        hasher.Update(in.begin(), in.begin() + 500);
        hasher.Update(in.begin(), in.begin() + 500);
        hasher.Update(in.begin(), in.begin() + 750);
        hasher.Update(in.begin(), in.begin() + 333);
        hasher.Update(in.begin(), in.begin() + 167);

        ASSERT_EQ("79e7958997241a7ffe484e14cbe1a41a088aa70b", hasher.Finish().ToHexString());
    }

    {
        // 1000 'a' followed by 1000 'b'.
        Sha1Hasher hasher;

        std::string inA(1000, 'a');
        std::string inB(1000, 'b');

        hasher.Update(inA.begin(), inA.begin() + 100);
        hasher.Update(inA.begin(), inA.begin() + 255);
        hasher.Update(inA.begin(), inA.begin() + 645);

        hasher.Update(inB.begin(), inB.begin() + 33);
        hasher.Update(inB.begin(), inB.begin() + 701);
        hasher.Update(inB.begin(), inB.begin() + 266);

        ASSERT_EQ("246f7ca16d5edebf7a5df7ddeab7c044745942ec", hasher.Finish().ToHexString());
    }
}

TEST(Sha1Tests, ResetTest)
{
    Sha1Hasher hasher;

    {
        const char * in = "abc";
        hasher.Update(in, in + strlen(in));
    }

    ASSERT_EQ("a9993e364706816aba3e25717850c26c9cd0d89d", hasher.Finish().ToHexString());

    hasher.Reset();

    {
        const char * in = "message digest";
        hasher.Update(in, in + strlen(in));
    }

    ASSERT_EQ("c12252ceda8be8994d5fa0290a47231c1d16aae3", hasher.Finish().ToHexString());

    hasher.Reset();

    ASSERT_EQ("da39a3ee5e6b4b0d3255bfef95601890afd80709", hasher.Finish().ToHexString());
}
