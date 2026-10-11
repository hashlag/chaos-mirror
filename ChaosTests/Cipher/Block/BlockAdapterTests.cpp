#include <gtest/gtest.h>
#include "TestHelpers/AssertThrowEx.hpp"

#include <cstring>
#include <cstdint>
#include <vector>

#include "Cipher/Block/Des/DesCrypt.hpp"
#include "Cipher/Block/Mode/Ecb.hpp"
#include "Cipher/Block/BlockAdapter.hpp"
#include "Padding/PadderPkcs7.hpp"
#include "Service/ChaosException.hpp"

using namespace Chaos::Cipher::Block;
using namespace Chaos::Cipher::Block::Mode;
using namespace Chaos::Padding;

TEST(BlockAdapterTests, EncryptTest)
{
    using Adapter = BlockAdapter<EcbMode<Des::DesCrypt, PadderPkcs7>>;

    {
        const char * str = "smoke and mirrors";
        std::vector<uint8_t> data(str, str + strlen(str));
        std::vector<uint8_t> key = { 0x0c, 0xfd, 0x01, 0xa3, 0x60, 0xd0, 0x15, 0xa6 };

        std::vector<uint8_t> expected = { 0x84, 0x39, 0xcd, 0xe5, 0x1f, 0x3d,
                                          0x2a, 0x11, 0x63, 0xc3, 0x56, 0x28,
                                          0xf5, 0x89, 0xdb, 0xc4, 0xa6, 0xca,
                                          0x52, 0xb3, 0xa8, 0xce, 0x64, 0x2d };

        ASSERT_EQ(expected, Adapter::Encrypt(key, data));
    }

    {
        std::vector<uint8_t> data = {};
        std::vector<uint8_t> key = { 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb };

        std::vector<uint8_t> expected = { 0xef, 0xe2, 0x4d, 0xe9, 0x9d, 0xe7, 0x9b, 0xbf };

        ASSERT_EQ(expected, Adapter::Encrypt(key, data));
    }

    {
        std::vector<uint8_t> data = { 0x96, 0x9f, 0x42, 0xd3, 0x47, 0x10, 0x4d, 0xb4, 0x89, 0x54,
                                      0x5c, 0xad, 0x0a, 0xb9, 0xac, 0x4e, 0xbf, 0x00, 0x1a, 0x47,
                                      0x3d, 0xd1, 0xe7, 0xb3, 0x70, 0xb7, 0x4e, 0xd9, 0x73, 0x7d,
                                      0xb3, 0x24 };
        std::vector<uint8_t> key = { 0xe9, 0xeb, 0x1f, 0xfa, 0x39, 0x95, 0xf0, 0xb9 };

        std::vector<uint8_t> expected = { 0x53, 0x06, 0x73, 0x79, 0xb8, 0xd7, 0xbe, 0x5d, 0x6e, 0xa0,
                                          0x1f, 0x03, 0x46, 0x07, 0xd6, 0x48, 0x65, 0x4f, 0x9a, 0x8f,
                                          0x1a, 0xe4, 0xa7, 0x7f, 0x13, 0xc9, 0x06, 0x8c, 0x57, 0xbd,
                                          0x79, 0x5e, 0x3d, 0x21, 0x02, 0x13, 0x5f, 0xae, 0xc9, 0x45 };

        ASSERT_EQ(expected, Adapter::Encrypt(key, data));
    }

    {
        std::vector<uint8_t> data = { 0x51, 0x89, 0x9f, 0x0c, 0x32, 0x9b, 0x1d };
        uint8_t key[] = { 0x28, 0x1c, 0xf3, 0x11, 0xce, 0xc6, 0xc2, 0x38 };

        std::vector<uint8_t> expected = { 0x64, 0x32, 0x13, 0xe7, 0x31, 0x06, 0xc6, 0x6f };

        ASSERT_EQ(expected, Adapter::Encrypt({ key, key + std::size(key) }, data));
    }
}

TEST(BlockAdapterTests, InvalidKeyTest)
{
    using Adapter = BlockAdapter<EcbMode<Des::DesCrypt, PadderPkcs7>>;

    {
        std::vector<uint8_t> key = { 0x01 };

        ASSERT_THROW_EX(Adapter::Key{ key },
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("DesCrypt::Key: invalid key length (8 bytes required)",
                                      ex.GetMessage());
                        });

        ASSERT_THROW_EX((Adapter::Key{ key.begin(), key.end() }),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("DesCrypt::Key: invalid key length (8 bytes required)",
                                      ex.GetMessage());
                        });
    }

    {
        std::vector<uint8_t> data = { 0x51, 0x89, 0x9f, 0x0c, 0x32, 0x9b, 0x1d };
        std::vector<uint8_t> key = { 0xe9, 0xeb, 0x11, 0x1f, 0xfa, 0xb3, 0x39, 0x95, 0xf0, 0xb9 };

        ASSERT_THROW_EX(Adapter::Encrypt(key, data),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("DesCrypt::Key: invalid key length (8 bytes required)",
                                      ex.GetMessage());
                        });
    }

    {
        std::vector<uint8_t> data = { 0x51, 0x89, 0x9f, 0x0c, 0x32, 0x9b, 0x1d };
        uint8_t key[] = { 0x28, 0x1c, 0xf3, 0x11, 0xce, 0xc6, 0xc2 };

        ASSERT_THROW_EX(Adapter::Encrypt({ key, key + std::size(key) }, data),
                        Chaos::Service::ChaosException,
                        {
                            ASSERT_EQ("DesCrypt::Key: invalid key length (8 bytes required)",
                                      ex.GetMessage());
                        });
    }
}
