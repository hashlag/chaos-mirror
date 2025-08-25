#include <gtest/gtest.h>

#include "Hash/Md5.hpp"
#include "Mac/Hmac.hpp"

using namespace Chaos::Mac::Hmac;
using namespace Chaos::Hash::Md5;

TEST(HmacTests, RfcTest)
{
    struct Helper
    {
        std::string operator()(const char * key, const char * data) const
        {
            Hmac<Md5Hasher> hmac(key, key + strlen(key));
            hmac.Update(data, data + strlen(data));
            return hmac.Finish().ToHexString();
        }
    };

    Helper hmacMd5;

    {
        const char * key = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
        const char * data = "Hi There";

        ASSERT_EQ("9294727a3638bb1c13f48ef8158bfc9d", hmacMd5(key, data));
    }

    {
        const char * key = "Jefe";
        const char * data = "what do ya want for nothing?";

        ASSERT_EQ("750c783e6ab0b503eaa86e310a5db738", hmacMd5(key, data));
    }

    {
        uint8_t key[] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                          0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
        uint8_t data[] = { 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                           0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                           0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                           0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                           0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd };

        Hmac<Md5Hasher> hmacMd5(key, key + std::size(key));
        hmacMd5.Update(data, data + std::size(data));

        ASSERT_EQ("56be34521d144c88dbb8c733f0e8b3f6", hmacMd5.Finish().ToHexString());
    }
}

TEST(HmacTests, LongKeyTest)
{
    struct Helper
    {
        std::string operator()(const char * key, const char * data) const
        {
            Hmac<Md5Hasher> hmac(key, key + strlen(key));
            hmac.Update(data, data + strlen(data));
            return hmac.Finish().ToHexString();
        }
    };

    Helper hmacMd5;

    {
        const char * key = "Passages from the Life of a Philosopher (1864), ch. 8 \"Of the Analytical Engine\"";
        const char * data = "As soon as an Analytical Engine exists, it will necessarily guide the future course of the science.";

        ASSERT_EQ("99459b85e800f3e5eab24e1c945794f8", hmacMd5(key, data));
    }
}

TEST(HmacTests, UninitializedHmacTest)
{
    std::array<uint8_t, 10> in;
    in.fill(0);

    {
        Hmac<Md5Hasher> hmac;

        ASSERT_THROW(hmac.Update(in.begin(), in.end()), Chaos::Service::ChaosException);
        ASSERT_THROW(hmac.Finish(), Chaos::Service::ChaosException);
    }
}
