#ifndef CHAOS_CIPHER_BLOCK_KEY_HPP
#define CHAOS_CIPHER_BLOCK_KEY_HPP

#include <concepts>
#include <cstdint>

namespace Chaos::Cipher::Block
{

template<typename T>
concept Key = requires
{
    requires std::constructible_from<T, uint8_t *, uint8_t *>;
};

} // namespace Chaos::Cipher::Block

#endif // CHAOS_CIPHER_BLOCK_KEY_HPP
