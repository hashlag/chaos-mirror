#ifndef CHAOS_PADDING_PADDERISO7816_HPP
#define CHAOS_PADDING_PADDERISO7816_HPP

#include <cstdint>

#include "Padding/Padder.hpp"

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
    }
};

} // namespace Chaos::Padding

#endif // CHAOS_PADDING_PADDERISO7816_HPP
