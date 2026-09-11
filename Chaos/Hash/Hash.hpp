#ifndef CHAOS_HASH_HASH_HPP
#define CHAOS_HASH_HASH_HPP

#include <concepts>
#include <string>

namespace Chaos::Hash
{

template<typename T>
concept Hash = requires(const T constHash)
{
    constHash.GetRawDigest();
    { constHash.ToHexString() } -> std::same_as<std::string>;
};

} // namespace Chaos::Hash

#endif // CHAOS_HASH_HASH_HPP
