#include <gtest/gtest.h>

#include "Hash/Md4.hpp"

using namespace Chaos::Hash::Md4;

TEST(Md4Tests, RFCTest)
{
    struct Helper
    {
        std::string operator()(const char * in) const
        {
            Md4Hasher hasher;
            hasher.Update(in, in + strlen(in));
            return hasher.Finish().ToHexString();
        }
    };

    Helper hash;

    ASSERT_EQ("31d6cfe0d16ae931b73c59d7e0c089c0", hash(""));
    ASSERT_EQ("bde52cb31de33e46245e05fbdbd6fb24", hash("a"));
    ASSERT_EQ("a448017aaf21d8525fc10ae87aa6729d", hash("abc"));
    ASSERT_EQ("d9130a8164549fe818874806e1c7014b", hash("message digest"));
    ASSERT_EQ("d79e1c308aa5bbcdeea8ed63df412da9", hash("abcdefghijklmnopqrstuvwxyz"));
    ASSERT_EQ("043f8582f241db351ce627e153e7f0e4", hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
    ASSERT_EQ("e33b4ddc9c38f2199c3e7b164fcc0536", hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890"));
}

TEST(Md4Tests, PartialUpdateTest)
{
    {
        // "a"
        Md4Hasher hasher;

        {
            const char * in = "a";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "";
            hasher.Update(in, in + strlen(in));
        }

        ASSERT_EQ("bde52cb31de33e46245e05fbdbd6fb24", hasher.Finish().ToHexString());
    }

    {
        // "abc"
        Md4Hasher hasher;

        {
            const char * in = "ab";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "c";
            hasher.Update(in, in + strlen(in));
        }

        ASSERT_EQ("a448017aaf21d8525fc10ae87aa6729d", hasher.Finish().ToHexString());
    }

    {
        // "message digest"
        Md4Hasher hasher;

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

        ASSERT_EQ("d9130a8164549fe818874806e1c7014b", hasher.Finish().ToHexString());
    }

    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        Md4Hasher hasher;

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

        ASSERT_EQ("e33b4ddc9c38f2199c3e7b164fcc0536", hasher.Finish().ToHexString());
    }
}

TEST(Md4Tests, LongInputTest)
{
    struct Helper
    {
        std::string operator()(const char * in) const
        {
            Md4Hasher hasher;
            hasher.Update(in, in + strlen(in));
            return hasher.Finish().ToHexString();
        }
    };

    Helper hash;

    // 2500 zeros ('0').
    ASSERT_EQ("20de61fc6dc2134f7a7bbcf43fd923e6", hash(std::string(2500, '0').c_str()));
    // 1000 'a' followed by 1000 'b'.
    ASSERT_EQ("cbabb47a57b10e0028ec7f519c66f229", hash((std::string(1000, 'a') +
                                                        std::string(1000, 'b')).c_str()));
}

TEST(Md4Tests, LongInputPartialUpdateTest)
{
    {
        // 2500 zeros ('0').
        Md4Hasher hasher;

        std::string in(750, '0');

        hasher.Update(in.begin(), in.begin() + 250);
        hasher.Update(in.begin(), in.begin() + 500);
        hasher.Update(in.begin(), in.begin() + 500);
        hasher.Update(in.begin(), in.begin() + 750);
        hasher.Update(in.begin(), in.begin() + 333);
        hasher.Update(in.begin(), in.begin() + 167);

        ASSERT_EQ("20de61fc6dc2134f7a7bbcf43fd923e6", hasher.Finish().ToHexString());
    }

    {
        // 1000 'a' followed by 1000 'b'.
        Md4Hasher hasher;

        std::string inA(1000, 'a');
        std::string inB(1000, 'b');

        hasher.Update(inA.begin(), inA.begin() + 100);
        hasher.Update(inA.begin(), inA.begin() + 255);
        hasher.Update(inA.begin(), inA.begin() + 645);

        hasher.Update(inB.begin(), inB.begin() + 33);
        hasher.Update(inB.begin(), inB.begin() + 701);
        hasher.Update(inB.begin(), inB.begin() + 266);

        ASSERT_EQ("cbabb47a57b10e0028ec7f519c66f229", hasher.Finish().ToHexString());
    }
}

TEST(Md4Tests, ResetTest)
{
    Md4Hasher hasher;

    {
        const char * in = "abc";
        hasher.Update(in, in + strlen(in));
    }

    ASSERT_EQ("a448017aaf21d8525fc10ae87aa6729d", hasher.Finish().ToHexString());

    hasher.Reset();

    {
        const char * in = "message digest";
        hasher.Update(in, in + strlen(in));
    }

    ASSERT_EQ("d9130a8164549fe818874806e1c7014b", hasher.Finish().ToHexString());

    hasher.Reset();

    ASSERT_EQ("31d6cfe0d16ae931b73c59d7e0c089c0", hasher.Finish().ToHexString());
}
