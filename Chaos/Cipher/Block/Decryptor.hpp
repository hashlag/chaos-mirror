#ifndef CHAOS_CIPHER_BLOCK_DECRYPTOR_HPP
#define CHAOS_CIPHER_BLOCK_DECRYPTOR_HPP

namespace Chaos::Cipher::Block
{

template<typename T>
class Decryptor
{
public:
    template<typename OutputIt, typename InputIt>
    void DecryptBlock(OutputIt out, InputIt inBegin, InputIt inEnd)
    {
        Impl().DecryptBlock(out, inBegin, inEnd);
    }

    template<typename Block>
    auto DecryptBlock(Block block)
    {
        return Impl().DecryptBlock(block);
    }

    auto GetBlockSize()
    {
        return Impl().GetBlockSize();
    }

protected:
    Decryptor() = default;

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

#endif // CHAOS_CIPHER_BLOCK_DECRYPTOR_HPP
