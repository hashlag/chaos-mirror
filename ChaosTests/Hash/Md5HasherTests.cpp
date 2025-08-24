#include <gtest/gtest.h>

#include "Hash/Md5.hpp"

using namespace Chaos::Hash::Md5;

TEST(Md5Tests, RfcTest)
{
    struct Helper
    {
        std::string operator()(const char * in) const
        {
            Md5Hasher hasher;
            hasher.Update(in, in + strlen(in));
            return hasher.Finish().ToHexString();
        }
    };

    Helper hash;

    ASSERT_EQ("d41d8cd98f00b204e9800998ecf8427e", hash(""));
    ASSERT_EQ("0cc175b9c0f1b6a831c399e269772661", hash("a"));
    ASSERT_EQ("900150983cd24fb0d6963f7d28e17f72", hash("abc"));
    ASSERT_EQ("f96b697d7cb7938d525a2f31aaf161d0", hash("message digest"));
    ASSERT_EQ("c3fcd3d76192e4007dfb496cca67e13b", hash("abcdefghijklmnopqrstuvwxyz"));
    ASSERT_EQ("d174ab98d277d9f5a5611c2c9f419d9f", hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
    ASSERT_EQ("57edf4a22be3c955ac49da2e2107b67a", hash("12345678901234567890123456789012345678901234567890123456789012345678901234567890"));
}

TEST(Md5Tests, PartialUpdateTest)
{
    {
        // "a"
        Md5Hasher hasher;

        {
            const char * in = "a";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "";
            hasher.Update(in, in + strlen(in));
        }

        ASSERT_EQ("0cc175b9c0f1b6a831c399e269772661", hasher.Finish().ToHexString());
    }

    {
        // "abc"
        Md5Hasher hasher;

        {
            const char * in = "ab";
            hasher.Update(in, in + strlen(in));
        }

        {
            const char * in = "c";
            hasher.Update(in, in + strlen(in));
        }

        ASSERT_EQ("900150983cd24fb0d6963f7d28e17f72", hasher.Finish().ToHexString());
    }

    {
        // "message digest"
        Md5Hasher hasher;

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

        ASSERT_EQ("f96b697d7cb7938d525a2f31aaf161d0", hasher.Finish().ToHexString());
    }

    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        Md5Hasher hasher;

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

        ASSERT_EQ("57edf4a22be3c955ac49da2e2107b67a", hasher.Finish().ToHexString());
    }
}

TEST(Md5Tests, LongInputTest)
{
    struct Helper
    {
        std::string operator()(const char * in) const
        {
            Md5Hasher hasher;
            hasher.Update(in, in + strlen(in));
            return hasher.Finish().ToHexString();
        }
    };

    Helper hash;

    // 2500 zeros ('0').
    ASSERT_EQ("17aa376e13f65b7a4cb1a4913b5e748c", hash(std::string(2500, '0').c_str()));
    // 1000 'a' followed by 1000 'b'.
    ASSERT_EQ("5ede0802e614ef9cccc73dc02f04c032", hash((std::string(1000, 'a') +
                                                        std::string(1000, 'b')).c_str()));
}

TEST(Md5Tests, LongInputPartialUpdateTest)
{
    {
        // 2500 zeros ('0').
        Md5Hasher hasher;

        std::string in(750, '0');

        hasher.Update(in.begin(), in.begin() + 250);
        hasher.Update(in.begin(), in.begin() + 500);
        hasher.Update(in.begin(), in.begin() + 500);
        hasher.Update(in.begin(), in.begin() + 750);
        hasher.Update(in.begin(), in.begin() + 333);
        hasher.Update(in.begin(), in.begin() + 167);

        ASSERT_EQ("17aa376e13f65b7a4cb1a4913b5e748c", hasher.Finish().ToHexString());
    }

    {
        // 1000 'a' followed by 1000 'b'.
        Md5Hasher hasher;

        std::string inA(1000, 'a');
        std::string inB(1000, 'b');

        hasher.Update(inA.begin(), inA.begin() + 100);
        hasher.Update(inA.begin(), inA.begin() + 255);
        hasher.Update(inA.begin(), inA.begin() + 645);

        hasher.Update(inB.begin(), inB.begin() + 33);
        hasher.Update(inB.begin(), inB.begin() + 701);
        hasher.Update(inB.begin(), inB.begin() + 266);

        ASSERT_EQ("5ede0802e614ef9cccc73dc02f04c032", hasher.Finish().ToHexString());
    }
}

TEST(Md5Tests, ResetTest)
{
    Md5Hasher hasher;

    {
        const char * in = "abc";
        hasher.Update(in, in + strlen(in));
    }

    ASSERT_EQ("900150983cd24fb0d6963f7d28e17f72", hasher.Finish().ToHexString());

    hasher.Reset();

    {
        const char * in = "message digest";
        hasher.Update(in, in + strlen(in));
    }

    ASSERT_EQ("f96b697d7cb7938d525a2f31aaf161d0", hasher.Finish().ToHexString());

    hasher.Reset();

    ASSERT_EQ("d41d8cd98f00b204e9800998ecf8427e", hasher.Finish().ToHexString());
}
