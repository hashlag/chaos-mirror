#include <gtest/gtest.h>

#include <cstring>
#include <cstdint>
#include <iterator>
#include <vector>

#include "Cipher/Block/Mode/Ecb.hpp"
#include "Cipher/Block/Des/DesCrypt.hpp"
#include "Padding/PadderPkcs7.hpp"
#include "Service/ChaosException.hpp"

using namespace Chaos::Cipher::Block::Mode;
using namespace Chaos::Cipher::Block;
using namespace Chaos::Padding;

TEST(EcbModeTests, EncryptTest)
{
    struct Helper
    {
        std::vector<uint8_t> operator()(const std::vector<uint8_t> & data,
                                        const std::vector<uint8_t> & key)
        {
            Des::DesCrypt::Key desKey(key.begin(), key.end());
            EcbMode<Des::DesCrypt, PadderPkcs7>::Encryptor enc(desKey);

            std::vector<uint8_t> out;
            out.resize(enc.PredictMaxUpdateOutput(data.size()) +
                       enc.PredictMaxFinishOutput());

            uint64_t written = enc.Update(out.begin(), out.end(), data.begin(), data.end());
            written += enc.Finish(out.begin() + written, out.end());

            out.resize(written);
            return out;
        }
    };

    Helper ecbEnc;

    {
        std::vector<uint8_t> data = {};
        std::vector<uint8_t> key = { 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb, 0xaa, 0xbb };

        std::vector<uint8_t> expected = { 0xef, 0xe2, 0x4d, 0xe9, 0x9d, 0xe7, 0x9b, 0xbf };

        ASSERT_EQ(expected, ecbEnc(data, key));
    }

    {
        const char * str = "smoke and mirrors";
        std::vector<uint8_t> data(str, str + strlen(str));
        std::vector<uint8_t> key = { 0x0c, 0xfd, 0x01, 0xa3, 0x60, 0xd0, 0x15, 0xa6 };

        std::vector<uint8_t> expected = { 0x84, 0x39, 0xcd, 0xe5, 0x1f, 0x3d,
                                          0x2a, 0x11, 0x63, 0xc3, 0x56, 0x28,
                                          0xf5, 0x89, 0xdb, 0xc4, 0xa6, 0xca,
                                          0x52, 0xb3, 0xa8, 0xce, 0x64, 0x2d };

        ASSERT_EQ(expected, ecbEnc(data, key));
    }

    {
        std::vector<uint8_t> data = { 0x51, 0x89, 0x9f, 0x0c, 0x32, 0x9b, 0x1d };
        std::vector<uint8_t> key = { 0x28, 0x1c, 0xf3, 0x11, 0xce, 0xc6, 0xc2, 0x38 };

        std::vector<uint8_t> expected = { 0x64, 0x32, 0x13, 0xe7, 0x31, 0x06, 0xc6, 0x6f };

        ASSERT_EQ(expected, ecbEnc(data, key));
    }

    {
        std::vector<uint8_t> data = { 0x32, 0x00, 0x93, 0x61, 0xc6, 0x9a, 0x25, 0x25, 0x2e };
        std::vector<uint8_t> key = { 0x28, 0x1c, 0xf3, 0x11, 0xce, 0xc6, 0xc2, 0x38 };

        std::vector<uint8_t> expected = { 0xee, 0x5b, 0x16, 0x33, 0xad, 0x2d, 0x32, 0x42,
                                          0xdc, 0x0d, 0x9f, 0x87, 0x55, 0x5b, 0xb1, 0x53 };

        ASSERT_EQ(expected, ecbEnc(data, key));
    }

    {
        std::vector<uint8_t> data = { 0x4d, 0x0d, 0xfb, 0x59, 0xe6, 0xc4, 0xf2, 0xe7,
                                      0xab, 0x46, 0x4f, 0x59, 0x48, 0x11, 0x1b, 0x4f };
        std::vector<uint8_t> key = { 0x44, 0x0a, 0xb1, 0x6d, 0xe0, 0x67, 0x28, 0x9d };

        std::vector<uint8_t> expected = { 0x55, 0xc1, 0x6f, 0xbb, 0xb0, 0xf3, 0xd3, 0xa6, 0xb7, 0xe6, 0x12, 0xb4,
                                          0x49, 0x86, 0x64, 0x07, 0x82, 0xbb, 0x45, 0x46, 0x70, 0xae, 0x64, 0x5f };

        ASSERT_EQ(expected, ecbEnc(data, key));
    }

    {
        std::vector<uint8_t> data = { 0x8a, 0xe3, 0x85, 0xe0, 0x59, 0xe7, 0xee, 0xce, 0xc0, 0xbf, 0x50, 0x53,
                                      0x95, 0xbf, 0x4b, 0xdd, 0x3b, 0x02, 0x2f, 0xcb, 0xd0, 0xd3, 0x62, 0x60 };
        std::vector<uint8_t> key = { 0xe4, 0x60, 0xb9, 0xfa, 0x4b, 0x79, 0x6a, 0xf3 };

        std::vector<uint8_t> expected = { 0xf4, 0x46, 0x31, 0xc5, 0xe8, 0xff, 0xdc, 0xac, 0x6c, 0x0e, 0xe8, 0x0e,
                                          0x9f, 0xc2, 0xeb, 0xdf, 0xca, 0xac, 0xc3, 0xc0, 0xea, 0xba, 0x6e, 0xc2,
                                          0x33, 0x5d, 0x16, 0x39, 0x74, 0xd1, 0x1d, 0xe1 };

        ASSERT_EQ(expected, ecbEnc(data, key));
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

        ASSERT_EQ(expected, ecbEnc(data, key));
    }

    {
        std::vector<uint8_t> data = { 0xde, 0xbf, 0x28, 0x16, 0x0d, 0xfe, 0x64, 0xbf, 0xc6, 0xfd,
                                      0x2d, 0x32, 0x45, 0xb0, 0xb7, 0x53, 0xde, 0x5a, 0x8e, 0x45,
                                      0x87, 0xb3, 0x94, 0x0b, 0xdb, 0x9d, 0x23, 0x33, 0xd7, 0x8e,
                                      0x63, 0x2d, 0x56 };
        std::vector<uint8_t> key = { 0x3b, 0x4d, 0xdd, 0x0a, 0x28, 0xf5, 0x96, 0x36 };

        std::vector<uint8_t> expected = { 0xc2, 0x88, 0xe5, 0x27, 0xd1, 0xb4, 0xa5, 0xf9, 0xb6, 0x02,
                                          0x43, 0x3e, 0xae, 0x59, 0x43, 0xd4, 0xe5, 0x87, 0x20, 0xfe,
                                          0xd0, 0x34, 0x28, 0x6a, 0xef, 0xb1, 0x9e, 0x5a, 0xdf, 0xfb,
                                          0xf7, 0x94, 0xb4, 0x0c, 0xc2, 0x92, 0x4e, 0x73, 0xda, 0xca };

        ASSERT_EQ(expected, ecbEnc(data, key));
    }

    {
        std::vector<uint8_t> data = { 0x7e, 0x2c, 0x68, 0x20, 0x22, 0xb1, 0xdd, 0x6d, 0x6e, 0x8b, 0x8b,
                                      0x30, 0x99, 0xaf, 0x79, 0x2f, 0x6c, 0x95, 0x11, 0x8d, 0xd4, 0x2f,
                                      0xcf, 0x1d, 0xe6, 0xa0, 0xc7, 0x73, 0x48, 0xb1, 0x65, 0xa9, 0xf6,
                                      0xc5, 0x1c, 0x42, 0x2d, 0xdd, 0xcf, 0xf5, 0xd4, 0xee, 0xa5, 0xa7,
                                      0x69, 0xf9, 0x27, 0x93, 0xce };
        std::vector<uint8_t> key = { 0x3c, 0xd0, 0xab, 0xd3, 0xb4, 0xc3, 0xac, 0x53 };

        std::vector<uint8_t> expected = { 0xf7, 0x44, 0x18, 0x9b, 0x9d, 0x8d, 0xe1, 0x14, 0xcd, 0x0a, 0xdb, 0xbd,
                                          0x5b, 0xd1, 0x42, 0x6e, 0x17, 0x73, 0x60, 0x9e, 0x14, 0xad, 0xd2, 0x4c,
                                          0x33, 0x30, 0xdd, 0xb9, 0xf3, 0x46, 0xd0, 0x8d, 0xa6, 0x37, 0x49, 0xd7,
                                          0x90, 0x23, 0x05, 0xcc, 0x56, 0xde, 0x1f, 0xde, 0x39, 0x6c, 0x04, 0x97,
                                          0x1d, 0xaf, 0xb5, 0xff, 0xab, 0x47, 0xc8, 0x51 };

        ASSERT_EQ(expected, ecbEnc(data, key));
    }
}

TEST(EcbModeTests, EncryptManyUpdatesTest)
{
    struct Helper
    {
        Helper(const std::vector<uint8_t> & key)
            : Key_(key.begin(), key.end())
            , Enc_(Key_)
            , Written_(0)
        { }

        void Update(const std::vector<uint8_t> & data)
        {
            Out_.resize(Out_.size() + Enc_.PredictMaxUpdateOutput(data.size()));

            Written_ += Enc_.Update(Out_.begin() + Written_, Out_.end(),
                                    data.begin(), data.end());
        }

        std::vector<uint8_t> Finish()
        {
            Out_.resize(Out_.size() + Enc_.PredictMaxFinishOutput());

            Written_ += Enc_.Finish(Out_.begin() + Written_, Out_.end());
            Out_.resize(Written_);

            return Out_;
        }

        Des::DesCrypt::Key Key_;
        EcbMode<Des::DesCrypt, PadderPkcs7>::Encryptor Enc_;

        std::vector<uint8_t> Out_;
        uint64_t Written_;
    };

    {
        std::vector<uint8_t> key = { 0xab, 0x39, 0x20, 0xea, 0xaa, 0x95, 0x1c, 0x90 };

        std::vector<uint8_t> data1 = { 0x97, 0x65, 0xe2, 0xb1, 0xae, 0x3e, 0x55, 0xff, 0x1d };
        std::vector<uint8_t> data2 = { 0xac, 0x8a, 0xa6, 0xac, 0xa5, 0x9a, 0xf9, 0xb6 };
        std::vector<uint8_t> data3 = { 0x3c, 0xba, 0x95, 0x5e, 0x78, 0x29, 0x22, 0x7c, 0x12, 0x7e, 0x4c };

        std::vector<uint8_t> expected = { 0xf4, 0xde, 0x9a, 0xe4, 0x78, 0x8c, 0xf2, 0xe6, 0x75, 0x34, 0xe7,
                                          0x9f, 0xe8, 0x16, 0x09, 0x12, 0x55, 0x75, 0x5b, 0xe4, 0x21, 0x65,
                                          0x98, 0x0e, 0xc6, 0x7a, 0x62, 0xf6, 0x88, 0xcd, 0x3e, 0x83 };

        Helper ecbEnc(key);

        ecbEnc.Update(data1);
        ecbEnc.Update(data2);
        ecbEnc.Update(data3);

        ASSERT_EQ(expected, ecbEnc.Finish());
    }

    {
        std::vector<uint8_t> key = { 0xd5, 0xc1, 0x3a, 0xcc, 0x6f, 0x86, 0x1d, 0x4b };

        std::vector<uint8_t> data1 = { 0x43, 0x73, 0x1b, 0xde, 0xbd, 0xfe, 0x16, 0x58 };
        std::vector<uint8_t> data2 = { 0x8c, 0x16, 0x13, 0x53, 0x22, 0x66, 0xb4, 0xf2 };
        std::vector<uint8_t> data3 = { 0x25, 0xcf, 0xcd, 0xab, 0x7d, 0x29, 0x9a, 0xd7 };

        std::vector<uint8_t> expected = { 0x5f, 0x18, 0x61, 0x15, 0x72, 0x75, 0x73, 0xb3, 0x44,
                                          0xa5, 0xf0, 0x46, 0xa9, 0x4b, 0x7e, 0x5e, 0x5b, 0x88,
                                          0x46, 0x07, 0x5e, 0x33, 0x16, 0x01, 0x69, 0x13, 0x76,
                                          0x8b, 0x7f, 0xbc, 0xf2, 0x75 };

        Helper ecbEnc(key);

        ecbEnc.Update(data1);
        ecbEnc.Update(data2);
        ecbEnc.Update(data3);

        ASSERT_EQ(expected, ecbEnc.Finish());
    }

    {
        std::vector<uint8_t> key = { 0xc0, 0x98, 0x56, 0xb3, 0x27, 0xc9, 0x78, 0x89 };

        std::vector<uint8_t> data1 = { 0xb7 };
        std::vector<uint8_t> data2 = { 0xb3 };
        std::vector<uint8_t> data3 = { 0x95, 0x56, 0xc0, 0x9f, 0x74, 0xd0, 0x49, 0xb5 };
        std::vector<uint8_t> data4 = { 0x15 };

        std::vector<uint8_t> expected = { 0xf9, 0x79, 0x6d, 0x46, 0xb6, 0x4a, 0xa8, 0xaa, 0x82,
                                          0xb9, 0xca, 0x65, 0xe9, 0x3c, 0xa8, 0xdc };

        Helper ecbEnc(key);

        ecbEnc.Update(data1);
        ecbEnc.Update(data2);
        ecbEnc.Update(data3);
        ecbEnc.Update(data4);

        ASSERT_EQ(expected, ecbEnc.Finish());
    }

    {
        std::vector<uint8_t> key = { 0xcb, 0x22, 0x90, 0x27, 0x87, 0x42, 0xd1, 0x58 };

        std::vector<uint8_t> data1 = { 0xca, 0x40, 0xeb, 0x08, 0x75, 0x62, 0x41 };
        std::vector<uint8_t> data2 = { 0x16, 0xa4, 0x12, 0x21, 0x3d, 0x5a, 0xf2, 0xb4, 0xa7, 0xb5, 0xa7 };
        std::vector<uint8_t> data3 = { 0x59, 0x51, 0xd0, 0x41, 0x21, 0xf0, 0x2b, 0x76,
                                       0xd8, 0xe4, 0x60, 0xb5, 0xab, 0xd8, 0x25, 0x29 };
        std::vector<uint8_t> data4 = { 0x94, 0x9f, 0xed };
        std::vector<uint8_t> data5 = { 0x1a, 0xa1, 0x57, 0x35, 0x2c };

        std::vector<uint8_t> expected = { 0xfb, 0x9d, 0x21, 0x86, 0x9b, 0xf1, 0x79, 0xeb, 0x6c,
                                          0xcf, 0xcc, 0xe7, 0x55, 0x48, 0x05, 0x42, 0x37, 0x23,
                                          0xcc, 0xda, 0x82, 0x8f, 0xe7, 0x5a, 0x08, 0x85, 0x00,
                                          0x0b, 0x38, 0x5f, 0x54, 0x53, 0xf9, 0x40, 0x59, 0xc7,
                                          0xf3, 0x06, 0x10, 0x10, 0xed, 0xfc, 0x76, 0xff, 0xe6,
                                          0x55, 0xb0, 0xe1 };

        Helper ecbEnc(key);

        ecbEnc.Update(data1);
        ecbEnc.Update(data2);
        ecbEnc.Update(data3);
        ecbEnc.Update(data4);
        ecbEnc.Update(data5);

        ASSERT_EQ(expected, ecbEnc.Finish());
    }
}

TEST(EcbModeTests, EncryptLongInputTest)
{
    struct Helper
    {
        Helper(const std::vector<uint8_t> & key)
            : Key_(key.begin(), key.end())
            , Enc_(Key_)
            , Written_(0)
        { }

        void Update(const std::vector<uint8_t> & data)
        {
            Out_.resize(Out_.size() + Enc_.PredictMaxUpdateOutput(data.size()));

            Written_ += Enc_.Update(Out_.begin() + Written_, Out_.end(),
                                    data.begin(), data.end());
        }

        void Update(std::vector<uint8_t>::const_iterator begin, std::vector<uint8_t>::const_iterator end)
        {
            Out_.resize(Out_.size() + Enc_.PredictMaxUpdateOutput(std::distance(begin, end)));
            Written_ += Enc_.Update(Out_.begin() + Written_, Out_.end(), begin, end);
        }

        std::vector<uint8_t> Finish()
        {
            Out_.resize(Out_.size() + Enc_.PredictMaxFinishOutput());

            Written_ += Enc_.Finish(Out_.begin() + Written_, Out_.end());
            Out_.resize(Written_);

            return Out_;
        }

        Des::DesCrypt::Key Key_;
        EcbMode<Des::DesCrypt, PadderPkcs7>::Encryptor Enc_;

        std::vector<uint8_t> Out_;
        uint64_t Written_;
    };

    {
        std::vector<uint8_t> key = { 0x27, 0x07, 0x7c, 0xc9, 0xd2, 0xbe, 0x76, 0x6c };
        std::vector<uint8_t> data(2048, 0xab);

        std::vector<uint8_t> expected;

        {
            std::vector<uint8_t> block = { 0x90, 0xf0, 0x72, 0xae, 0xcc, 0x98, 0x93, 0x8d };

            for (int i = 0; i < 256; ++i)
            {
                expected.insert(expected.end(), block.begin(), block.end());
            }

            std::vector<uint8_t> lastBlock = { 0xce, 0x7c, 0x12, 0x8e, 0x8c, 0xc0, 0x88, 0x02 };
            expected.insert(expected.end(), lastBlock.begin(), lastBlock.end());
        }

        Helper ecbEnc(key);
        ecbEnc.Update(data);

        ASSERT_EQ(expected, ecbEnc.Finish());
    }

    {
        std::vector<uint8_t> key = { 0xcc, 0xc5, 0x08, 0x98, 0xe9, 0x8c, 0xeb, 0x23 };
        std::vector<uint8_t> data(4095, 0x7a);

        std::vector<uint8_t> expected;
        {
            std::vector<uint8_t> block = { 0xb7, 0x9f, 0x07, 0x2c, 0xe9, 0x54, 0x83, 0xc5 };

            for (int i = 0; i < 2048; ++i)
            {
                expected.insert(expected.end(), block.begin(), block.end());
            }

            std::vector<uint8_t> lastBlock = { 0x14, 0x59, 0x29, 0x72, 0x45, 0xb3, 0x03, 0xb3 };
            expected.insert(expected.end(), lastBlock.begin(), lastBlock.end());
        }

        Helper ecbEnc(key);

        ecbEnc.Update(data.begin(), data.begin() + 2340);
        ecbEnc.Update(data.begin(), data.begin() + 1171);
        ecbEnc.Update(data.begin(), data.begin() + 2925);
        ecbEnc.Update(data.begin(), data.begin() + 1);
        ecbEnc.Update(data.begin(), data.begin() + 4095);
        ecbEnc.Update(data.begin(), data.begin() + 586);
        ecbEnc.Update(data.begin(), data.begin() + 3510);
        ecbEnc.Update(data.begin(), data.begin() + 1756);

        ASSERT_EQ(expected, ecbEnc.Finish());
    }
}

TEST(EcbModeTests, EncryptInsufficientBufferTest)
{
    std::vector<uint8_t> key = { 0xcc, 0xc5, 0x08, 0x98, 0xe9, 0x8c, 0xeb, 0x23 };
    Des::DesCrypt::Key desKey(key.begin(), key.end());

    {
        std::vector<uint8_t> data(8, 0xaa);
        std::vector<uint8_t> out;

        EcbMode<Des::DesCrypt, PadderPkcs7>::Encryptor enc(desKey);

        ASSERT_THROW(enc.Update(out.begin(), out.end(), data.begin(), data.end()),
                     Chaos::Service::ChaosException);
    }

    {
        std::vector<uint8_t> data(8, 0xaa);
        std::vector<uint8_t> out(7, 0);

        EcbMode<Des::DesCrypt, PadderPkcs7>::Encryptor enc(desKey);

        ASSERT_THROW(enc.Update(out.begin(), out.end(), data.begin(), data.end()),
                     Chaos::Service::ChaosException);
    }

    {
        std::vector<uint8_t> data1(7, 0xaa);
        std::vector<uint8_t> data2(2, 0xbb);

        std::vector<uint8_t> out1(7, 0);
        std::vector<uint8_t> out2(2, 0);

        EcbMode<Des::DesCrypt, PadderPkcs7>::Encryptor enc(desKey);

        enc.Update(out1.begin(), out1.end(), data1.begin(), data1.end());

        ASSERT_THROW(enc.Update(out2.begin(), out2.end(), data2.begin(), data2.end()),
                     Chaos::Service::ChaosException);
    }

    {
        std::vector<uint8_t> data(8, 0xaa);
        std::vector<uint8_t> out(8, 0);

        EcbMode<Des::DesCrypt, PadderPkcs7>::Encryptor enc(desKey);

        uint64_t written = enc.Update(out.begin(), out.end(), data.begin(), data.end());

        ASSERT_THROW(written += enc.Finish(out.begin() + written, out.end()),
                     Chaos::Service::ChaosException);
    }

    {
        std::vector<uint8_t> data(15, 0xaa);
        std::vector<uint8_t> out(15, 0);

        EcbMode<Des::DesCrypt, PadderPkcs7>::Encryptor enc(desKey);

        uint64_t written = enc.Update(out.begin(), out.end(), data.begin(), data.end());

        ASSERT_THROW(written += enc.Finish(out.begin() + written, out.end()),
                     Chaos::Service::ChaosException);
    }
}
