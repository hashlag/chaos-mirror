#ifndef CHAOS_MAC_HMAC_HPP
#define CHAOS_MAC_HMAC_HPP

#include <cstdint>

#include "Hash/Hasher.hpp"
#include "Service/SeArray.hpp"
#include "Service/ChaosException.hpp"

namespace Chaos::Mac::Hmac
{

template<Hash::Hasher HasherImpl>
class Hmac
{
public:
    Hmac()
        : IsInitialized_(false)
    { }

    Hmac(const Hmac & other) = delete;
    Hmac(Hmac && other) = delete;

    Hmac & operator=(const Hmac & other) = delete;
    Hmac & operator=(Hmac && other) = delete;

    template<typename InputIt>
    Hmac(InputIt keyBegin, InputIt keyEnd)
    {
        RekeyImpl(keyBegin, keyEnd);
    }

    template<typename InputIt>
    void Rekey(InputIt keyBegin, InputIt keyEnd)
    {
        RekeyImpl(keyBegin, keyEnd);
    }

    template<typename InputIt>
    void Update(InputIt begin, InputIt end)
    {
        EnsureInitialized();
        Hasher_.Update(begin, end);
    }

    typename HasherImpl::HashType Finish()
    {
        EnsureInitialized();

        auto innerDigest = Hasher_.Finish().GetRawDigest();

        Hasher_.Reset();

        KeyType opaddedKey = PadKey<OPAD_BYTE>(Key_);
        Hasher_.Update(opaddedKey.Begin(), opaddedKey.End());
        Hasher_.Update(innerDigest.begin(), innerDigest.end());

        return Hasher_.Finish();
    }

private:
    using KeyType = Service::SeArray<uint8_t, HasherImpl::BlockSize>;

    static constexpr uint8_t OPAD_BYTE = 0x5c;
    static constexpr uint8_t IPAD_BYTE = 0x36;

    HasherImpl Hasher_;
    KeyType Key_;

    bool IsInitialized_;

    void EnsureInitialized() const
    {
        if (!IsInitialized_)
        {
            throw Service::ChaosException("Hmac: not initialized");
        }
    }

    template<typename InputIt>
    static KeyType GenerateKey(InputIt keyBegin, InputIt keyEnd)
    {
        KeyType key;
        key.Fill(0);

        InputIt keyIt = keyBegin;
        uint64_t idx = 0;

        for (; keyIt != keyEnd && idx < key.Size();
               ++keyIt, ++idx)
        {
            key[idx] = *keyIt;
        }

        if (keyIt != keyEnd)
        {
            HasherImpl keyHasher;

            keyHasher.Update(key.Begin(), key.End());
            keyHasher.Update(keyIt, keyEnd);

            auto digest = keyHasher.Finish().GetRawDigest();
            static_assert(digest.size() <= HasherImpl::BlockSize);

            key.Fill(0);
            idx = 0;

            for (auto it = digest.begin();
                 it != digest.end() && idx < key.Size();
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

        for (auto it = key.Begin();
             it != key.End() && idx < paddedKey.Size();
             ++it, ++idx)
        {
            paddedKey[idx] = (*it) ^ PAD_BYTE;
        }

        return paddedKey;
    }

    template<typename InputIt>
    void RekeyImpl(InputIt keyBegin, InputIt keyEnd)
    {
        Key_ = GenerateKey(keyBegin, keyEnd);
        Hasher_.Reset();

        KeyType ipaddedKey = PadKey<IPAD_BYTE>(Key_);
        Hasher_.Update(ipaddedKey.Begin(), ipaddedKey.End());

        IsInitialized_ = true;
    }
};

} // namespace Chaos::Mac::Hmac

#endif // CHAOS_MAC_HMAC_HPP
