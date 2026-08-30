#ifndef CHAOS_HASH_HASHER_HPP
#define CHAOS_HASH_HASHER_HPP

#include <cstdint>

#include "Hash.hpp"

namespace Chaos::Hash
{

template<typename T>
concept Hasher = requires(T hasher, uint8_t * begin, uint8_t * end)
{
    hasher.Reset();
    hasher.Update(begin, end);
    { hasher.Finish() } -> Hash;
};

} // namespace Chaos::Hash

#endif // CHAOS_HASH_HASHER_HPP
