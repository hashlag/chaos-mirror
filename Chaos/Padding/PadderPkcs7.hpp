#ifndef CHAOS_PADDING_PADDERPKCS7_HPP
#define CHAOS_PADDING_PADDERPKCS7_HPP

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>

#include "Padding/Padder.hpp"
#include "Service/Branchless.hpp"
#include "Service/ChaosException.hpp"

namespace Chaos::Padding
{

class PadderPkcs7
{
public:
    template<typename OutputIt>
    static void Pad(OutputIt begin, OutputIt end)
    {
        auto dist = std::distance(begin, end);

        if (dist > 0 && dist <= std::numeric_limits<uint8_t>::max())
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
        uint8_t isOkay = ~Branchless::IsZero<uint8_t>(padSize);

        size_t suffixSize = 0;
        InputIt it = end;
        while (it != begin && suffixSize < std::numeric_limits<uint8_t>::max())
        {
            --it;
            ++suffixSize;

            isOkay &= (Branchless::Eq<uint8_t>(*it, padSize) |
                       Branchless::Gt<uint8_t, size_t>(suffixSize, padSize));
        }

        isOkay &= Branchless::Ge<uint8_t, size_t>(suffixSize, padSize);

        return
        {
            .IsOkay_ = Branchless::ToBool(isOkay),
            .PadSize_ = Branchless::Sel<uint8_t>(isOkay, padSize, 0)
        };
    }

private:
    using Branchless = Service::Branchless;
};

static_assert(Padder<PadderPkcs7>);

} // namespace Chaos::Padding

#endif // CHAOS_PADDING_PADDERPKCS7_HPP
