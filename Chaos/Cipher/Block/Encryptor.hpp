#ifndef CHAOS_CIPHER_BLOCK_ENCRYPTOR_HPP
#define CHAOS_CIPHER_BLOCK_ENCRYPTOR_HPP

namespace Chaos::Cipher::Block
{

template<typename T>
class Encryptor
{
public:
    template<typename OutputIt, typename InputIt>
    void EncryptBlock(OutputIt out, InputIt inBegin, InputIt inEnd)
    {
        Impl().EncryptBlock(out, inBegin, inEnd);
    }

    template<typename Block>
    auto EncryptBlock(Block block)
    {
        return Impl().EncryptBlock(block);
    }

    auto GetBlockSize()
    {
        return Impl().GetBlockSize();
    }

protected:
    Encryptor() = default;

private:
    const T & Impl() const
    {
        return static_cast<const T &>(*this);
    }

    T & Impl()
    {
        return static_cast<T &>(*this);
    }
};

} // namespace Chaos::Cipher::Block

#endif // CHAOS_CIPHER_BLOCK_ENCRYPTOR_HPP
