#ifndef CHAOS_CIPHER_BLOCK_BLOCKCIPHER_HPP
#define CHAOS_CIPHER_BLOCK_BLOCKCIPHER_HPP

#include <concepts>
#include <type_traits>

#include "BlockKey.hpp"
#include "BlockEncryptor.hpp"
#include "BlockDecryptor.hpp"

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

    requires BlockKey<typename T::Key>;
    requires BlockEncryptor<typename T::Encryptor>;
    requires BlockDecryptor<typename T::Decryptor>;
};

} // namespace Chaos::Cipher::Block

#endif // CHAOS_CIPHER_BLOCK_BLOCKCIPHER_HPP
