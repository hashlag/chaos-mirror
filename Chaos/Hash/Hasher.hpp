#ifndef CHAOS_HASH_HASHER_HPP
#define CHAOS_HASH_HASHER_HPP

#include <concepts>
#include <cstdint>
#include <type_traits>

#include "Hash.hpp"

namespace Chaos::Hash
{

template<typename T>
concept Hasher = requires(T hasher, uint8_t * begin, uint8_t * end)
{
    typename T::HashType;

    requires std::unsigned_integral<std::remove_cvref_t<decltype(T::BlockSizeBytes)>>;
    typename std::integral_constant<decltype(T::BlockSizeBytes), T::BlockSizeBytes>;

    hasher.Reset();
    hasher.Update(begin, end);
    { hasher.Finish() } -> Hash;
};

} // namespace Chaos::Hash

#endif // CHAOS_HASH_HASHER_HPP
