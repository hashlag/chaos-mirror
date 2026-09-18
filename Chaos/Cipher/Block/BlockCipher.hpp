#ifndef CHAOS_CIPHER_BLOCK_BLOCKCIPHER_HPP
#define CHAOS_CIPHER_BLOCK_BLOCKCIPHER_HPP

#include <concepts>
#include <type_traits>

#include "Key.hpp"
#include "Encryptor.hpp"
#include "Decryptor.hpp"

namespace Chaos::Cipher::Block
{

template<typename T>
concept BlockCipher = requires
{
    typename T::Block;
    typename T::Key;
    typename T::Encryptor;
    typename T::Decryptor;

    requires std::unsigned_integral<std::remove_cvref_t<decltype(T::BlockSize)>>;
    typename std::integral_constant<decltype(T::BlockSize), T::BlockSize>;

    requires std::unsigned_integral<std::remove_cvref_t<decltype(T::KeySize)>>;
    typename std::integral_constant<decltype(T::KeySize), T::KeySize>;

    requires Key<typename T::Key>;
    requires Encryptor<typename T::Encryptor>;
    requires Decryptor<typename T::Decryptor>;
};

} // namespace Chaos::Cipher::Block

#endif // CHAOS_CIPHER_BLOCK_BLOCKCIPHER_HPP
