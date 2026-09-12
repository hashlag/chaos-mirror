#ifndef CHAOS_CIPHER_BLOCK_DECRYPTOR_HPP
#define CHAOS_CIPHER_BLOCK_DECRYPTOR_HPP

#include <concepts>
#include <cstdint>
#include <type_traits>

namespace Chaos::Cipher::Block
{

template<typename T>
concept Decryptor = requires(const T constDecryptor,
                             typename T::Block block,
                             uint8_t * outBegin, uint8_t * outEnd,
                             uint8_t * inBegin, uint8_t * inEnd)
{
    typename T::Block;
    typename T::Key;
    requires std::constructible_from<T, typename T::Key>;

    requires std::unsigned_integral<std::remove_cvref_t<decltype(T::BlockSize)>>;
    typename std::integral_constant<decltype(T::BlockSize), T::BlockSize>;

    requires std::unsigned_integral<std::remove_cvref_t<decltype(T::KeySize)>>;
    typename std::integral_constant<decltype(T::KeySize), T::KeySize>;

    constDecryptor.DecryptBlock(outBegin, outEnd, inBegin, inEnd);
    { constDecryptor.DecryptBlock(block) } -> std::same_as<typename T::Block>;
    { constDecryptor.GetBlockSize() } -> std::unsigned_integral;
};

} // namespace Chaos::Cipher::Block

#endif // CHAOS_CIPHER_BLOCK_DECRYPTOR_HPP
