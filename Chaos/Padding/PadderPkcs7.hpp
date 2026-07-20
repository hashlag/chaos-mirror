#ifndef CHAOS_PADDING_PADDERPKCS7_HPP
#define CHAOS_PADDING_PADDERPKCS7_HPP

#include <climits>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <type_traits>

#include "Padding/Padder.hpp"
#include "Service/ChaosException.hpp"

namespace Chaos::Padding
{

class PadderPkcs7 : public Padder<PadderPkcs7>
{
public:
    template<typename OutputIt>
    static void Pad(OutputIt begin, OutputIt end)
    {
        auto dist = std::distance(begin, end);

        // TODO: dist > 0
        if (dist >= 0 && dist <= std::numeric_limits<uint8_t>::max())
        {
            for (OutputIt it = begin; it != end; ++it)
            {
                *it = static_cast<uint8_t>(dist);
            }
        }
        else
        {
            throw Service::ChaosException("PadderPkcs7::Pad(): invalid range");
        }
    }

    struct ComputeUnpadResult
    {
        bool IsOkay_;
        uint8_t PadSize_;
    };

    template<typename InputIt>
    static ComputeUnpadResult ComputeUnpad(InputIt begin, InputIt end) noexcept
    {
        if (begin == end)
        {
            return { .IsOkay_ = false, .PadSize_ = 0 };
        }

        const uint8_t padSize = *std::prev(end);
        uint8_t isOkay = ~BlIsZero<uint8_t>(padSize);

        size_t suffixSize = 0;
        InputIt it = end;
        while (it != begin && suffixSize < std::numeric_limits<uint8_t>::max())
        {
            --it;
            ++suffixSize;

            isOkay &= (BlEq<uint8_t>(*it, padSize) |
                       BlGt<uint8_t, size_t>(suffixSize, padSize));
        }

        isOkay &= BlGe<uint8_t, size_t>(suffixSize, padSize);

        return
        {
            .IsOkay_ = static_cast<bool>(isOkay),
            .PadSize_ = BlSel<uint8_t>(isOkay, padSize, 0)
        };
    }

private:
    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt BlMsb(InUInt in) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);

        constexpr uint8_t shift = (sizeof(InUInt) * CHAR_BIT) - 1;
        return static_cast<OutUInt>(0) - (in >> shift);
    }

    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt BlLt(InUInt lhs, InUInt rhs) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);
        static_assert(sizeof(InUInt) <= sizeof(uint64_t));

        const uint64_t lhsEx = lhs;
        const uint64_t rhsEx = rhs;

        return BlMsb<OutUInt>(lhsEx ^ ((lhsEx ^ rhsEx) | ((lhsEx - rhsEx) ^ lhsEx)));
    }

    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt BlIsZero(InUInt in) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);
        static_assert(sizeof(InUInt) <= sizeof(uint64_t));

        const uint64_t inEx = in;

        return BlMsb<OutUInt>(~inEx & (inEx - 1U));
    }

    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt BlEq(InUInt lhs, InUInt rhs) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);

        return BlIsZero<OutUInt, InUInt>(lhs ^ rhs);
    }

    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt BlGe(InUInt lhs, InUInt rhs) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);

        return ~BlLt<OutUInt>(lhs, rhs);
    }

    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt BlGt(InUInt lhs, InUInt rhs) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);

        return BlLt<OutUInt>(rhs, lhs);
    }

    template<typename UInt>
    static constexpr UInt BlSel(UInt mask, UInt onTrue, UInt onFalse) noexcept
    {
        static_assert(std::is_unsigned_v<UInt>);

        return (mask & onTrue) | (~mask & onFalse);
    }
};

} // namespace Chaos::Padding

#endif // CHAOS_PADDING_PADDERPKCS7_HPP
