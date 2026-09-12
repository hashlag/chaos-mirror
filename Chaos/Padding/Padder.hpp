#ifndef CHAOS_PADDING_PADDER_HPP
#define CHAOS_PADDING_PADDER_HPP

#include <cstdint>

namespace Chaos::Padding
{

template<typename T>
concept Padder = requires(uint8_t * begin, uint8_t * end)
{
    T::Pad(begin, end);
    { T::ComputeUnpad(begin, end) } noexcept;
};

} // namespace Chaos::Padding

#endif // CHAOS_PADDING_PADDER_HPP
