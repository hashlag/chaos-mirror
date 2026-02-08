#ifndef CHAOS_PADDING_PADPKCS7_HPP
#define CHAOS_PADDING_PADPKCS7_HPP

#include <cstdint>
#include <iterator>
#include <limits>

#include "Service/ChaosException.hpp"

namespace Chaos::Padding
{

class PadPkcs7
{
public:
    template<typename OutputIt>
    static void Pad(OutputIt begin, OutputIt end)
    {
        auto dist = std::distance(begin, end);

        if (dist >= 0 && dist <= std::numeric_limits<uint8_t>::max())
        {
            for (OutputIt it = begin; it != end; ++it)
            {
                *it = static_cast<uint8_t>(dist);
            }
        }
        else
        {
            throw Service::ChaosException("PadPkcs7::Pad(): invalid range");
        }
    }
};

} // namespace Chaos::Padding

#endif // CHAOS_PADDING_PADPKCS7_HPP
