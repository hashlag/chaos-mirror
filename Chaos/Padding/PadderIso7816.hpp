#ifndef CHAOS_PADDING_PADDERISO7816_HPP
#define CHAOS_PADDING_PADDERISO7816_HPP

#include <cstddef>
#include <cstdint>
#include <limits>

#include "Padding/Padder.hpp"
#include "Service/Branchless.hpp"
#include "Service/ChaosException.hpp"

namespace Chaos::Padding
{

class PadderIso7816 : public Padder<PadderIso7816>
{
public:
    template<typename OutputIt>
    static void Pad(OutputIt begin, OutputIt end)
    {
        OutputIt it = begin;

        if (it != end)
        {
            *it++ = static_cast<uint8_t>(0x80);

            for (; it != end; ++it)
            {
                *it = 0;
            }
        }
        else
        {
            throw Service::ChaosException("PadderIso7816::Pad(): invalid range");
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

        uint8_t padSizeIncrement = 1;
        uint8_t padSize = 0;

        uint8_t encountered0x80 = Branchless::FalseMask;
        uint8_t onlyZerosPast0x80 = Branchless::TrueMask;

        InputIt it = end;
        while (it != begin && padSize < std::numeric_limits<uint8_t>::max())
        {
            --it;

            const uint8_t byte = *it;

            padSizeIncrement = Branchless::Sel<uint8_t>(encountered0x80, 0, 1);
            encountered0x80 |= Branchless::Eq<uint8_t, uint8_t>(byte, 0x80);
            onlyZerosPast0x80 &= Branchless::IsZero<uint8_t, uint8_t>(byte) | encountered0x80;

            padSize += padSizeIncrement;
        }

        uint8_t isOkay = encountered0x80 & onlyZerosPast0x80;

        return
        {
            .IsOkay_ = static_cast<bool>(isOkay),
            .PadSize_ = Branchless::Sel<uint8_t>(isOkay, padSize, 0)
        };
    }

private:
    using Branchless = Service::Branchless;
};

} // namespace Chaos::Padding

#endif // CHAOS_PADDING_PADDERISO7816_HPP
