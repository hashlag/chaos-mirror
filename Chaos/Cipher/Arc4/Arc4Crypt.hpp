#ifndef CHAOS_CIPHER_ARC4CRYPT_HPP
#define CHAOS_CIPHER_ARC4CRYPT_HPP

#include "Arc4Gen.hpp"
#include "Service/ChaosException.hpp"

namespace Chaos::Cipher::Arc4
{

class Arc4Crypt
{
public:
    Arc4Crypt()
        : IsInitialized_(false)
    { }

    template<typename InputIt>
    Arc4Crypt(InputIt keyBegin, InputIt keyEnd)
    {
        RekeyImpl(keyBegin, keyEnd);
    }

    template<typename InputIt>
    void Rekey(InputIt keyBegin, InputIt keyEnd)
    {
        RekeyImpl(keyBegin, keyEnd);
    }

    template<typename OutputIt, typename InputIt>
    void Encrypt(OutputIt out, InputIt in, uint64_t count)
    {
        // TODO:
    }

    template<typename OutputIt, typename InputIt>
    void Decrypt(OutputIt out, InputIt in, uint64_t count)
    {
        // TODO:
    }

private:
    bool IsInitialized_;
    Arc4Gen Gen_;

    void EnsureInitialized() const
    {
        if (!IsInitialized_)
        {
            throw Service::ChaosException("Arc4Crypt: not initialized");
        }
    }

    template<typename InputIt>
    void RekeyImpl(InputIt keyBegin, InputIt keyEnd)
    {
        Gen_.Rekey(keyBegin, keyEnd);
        IsInitialized_ = true;
    }
};

} // namespace Chaos::Cipher::Arc4

#endif
