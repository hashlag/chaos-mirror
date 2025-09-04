#ifndef CHAOS_CIPHER_ARC4GEN_HPP
#define CHAOS_CIPHER_ARC4GEN_HPP

#include <array>
#include <cstdint>
#include <vector>

#include "Service/ChaosException.hpp"

namespace Chaos::Cipher::Arc4
{

class Arc4Gen
{
public:
    Arc4Gen()
        : IsInitialized_(false)
    { }

    template<typename InputIt>
    Arc4Gen(InputIt keyBegin, InputIt keyEnd)
    {
        RekeyImpl(keyBegin, keyEnd);
    }

    template<typename InputIt>
    void Rekey(InputIt keyBegin, InputIt keyEnd)
    {
        RekeyImpl(keyBegin, keyEnd);
    }

    template<typename OutputIt>
    void Generate(OutputIt out, uint64_t bytesCount)
    {
        EnsureInitialized();

        for (uint64_t cnt = 0; cnt < bytesCount; ++cnt)
        {
            Step(1);
            *out++ = Lookup_[static_cast<uint8_t>(Lookup_[I_] + Lookup_[J_])];
        }
    }

    void Drop(uint64_t bytesCount)
    {
        EnsureInitialized();
        Step(bytesCount);
    }

private:
    bool IsInitialized_;

    uint8_t I_;
    uint8_t J_;
    std::array<uint8_t, 256> Lookup_;

    void EnsureInitialized() const
    {
        if (!IsInitialized_)
        {
            throw Service::ChaosException("Arc4Gen: not initialized");
        }
    }

    template<typename InputIt>
    void RekeyImpl(InputIt keyBegin, InputIt keyEnd)
    {
        I_ = 0;
        J_ = 0;

        for (uint64_t idx = 0; idx < Lookup_.size(); ++idx)
        {
            Lookup_[idx] = static_cast<uint8_t>(idx);
        }

        std::vector<uint8_t> key(keyBegin, keyEnd);

        if (key.size() < 5)
        {
            throw Service::ChaosException("Arc4Gen: key is too small");
        }

        uint8_t a = 0;
        uint8_t b = 0;

        for (uint64_t idx = 0; idx < Lookup_.size(); ++idx)
        {
            a = static_cast<uint8_t>(idx);
            b = b + Lookup_[a] + key[a % key.size()];

            std::swap(Lookup_[a], Lookup_[b]);
        }

        IsInitialized_ = true;
    }

    void Step(uint64_t stepsCount)
    {
        for (uint64_t k = 0; k < stepsCount; ++k)
        {
            I_ = I_ + 1;
            J_ = J_ + Lookup_[I_];

            std::swap(Lookup_[I_], Lookup_[J_]);
        }
    }
};

} // namespace Chaos::Cipher::Arc4

#endif
