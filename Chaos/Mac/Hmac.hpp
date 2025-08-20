#ifndef CHAOS_MAC_HMAC_HPP
#define CHAOS_MAC_HMAC_HPP

#include <array>
#include <cstdint>
#include <type_traits>

#include "Hash/Hasher.hpp"

namespace Chaos::Mac::Hmac
{

template<typename HasherImpl,
         typename = std::enable_if_t<std::is_base_of_v<Hash::Hasher<HasherImpl>, HasherImpl>>>
class Hmac
{
public:
    template<typename InputIt>
    Hmac(InputIt keyBegin, InputIt keyEnd)
    {
        Key_ = GenerateKey(keyBegin, keyEnd);

        KeyType ipaddedKey = PadKey<IPAD_BYTE>(Key_);
        Hasher_.Update(ipaddedKey.begin(), ipaddedKey.end());
    }

    template<typename InputIt>
    void Update(InputIt begin, InputIt end)
    {
        Hasher_.Update(begin, end);
    }

    typename HasherImpl::HashType Finish()
    {
        auto innerDigest = Hasher_.Finish().GetRawDigest();

        Hasher_.Reset();

        KeyType opaddedKey = PadKey<OPAD_BYTE>(Key_);
        Hasher_.Update(opaddedKey.begin(), opaddedKey.end());
        Hasher_.Update(innerDigest.begin(), innerDigest.end());

        return Hasher_.Finish();
    }

private:
    using KeyType = std::array<uint8_t, HasherImpl::BLOCK_SIZE_BYTES>;

    static constexpr uint8_t OPAD_BYTE = 0x5c;
    static constexpr uint8_t IPAD_BYTE = 0x36;

    KeyType Key_;
    HasherImpl Hasher_;

    template<typename InputIt>
    static KeyType GenerateKey(InputIt keyBegin, InputIt keyEnd)
    {
        KeyType key;
        key.fill(0);

        InputIt keyIt = keyBegin;
        uint64_t idx = 0;

        for (; keyIt != keyEnd && idx < key.size();
               ++keyIt, ++idx)
        {
            key[idx] = *keyIt;
        }

        if (keyIt != keyEnd)
        {
            HasherImpl keyHasher;

            keyHasher.Update(key.begin(), key.end());
            keyHasher.Update(keyIt, keyEnd);

            auto digest = keyHasher.Finish().GetRawDigest();
            static_assert(digest.size() <= HasherImpl::BLOCK_SIZE_BYTES);

            key.fill(0);
            idx = 0;

            for (auto it = digest.begin();
                 it != digest.end() && idx < key.size();
                 ++it, ++idx)
            {
                key[idx] = *it;
            }
        }

        return key;
    }

    template<uint8_t PAD_BYTE>
    static KeyType PadKey(const KeyType & key)
    {
        static_assert(PAD_BYTE == IPAD_BYTE || PAD_BYTE == OPAD_BYTE);

        KeyType paddedKey;
        uint64_t idx = 0;

        for (auto it = key.cbegin();
             it != key.cend() && idx < paddedKey.size();
             ++it, ++idx)
        {
            paddedKey[idx] = (*it) ^ PAD_BYTE;
        }

        return paddedKey;
    }
};

} // namespace Chaos::Mac::Hmac

#endif
