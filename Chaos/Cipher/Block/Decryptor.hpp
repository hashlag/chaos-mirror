#ifndef CHAOS_CIPHER_BLOCK_DECRYPTOR_HPP
#define CHAOS_CIPHER_BLOCK_DECRYPTOR_HPP

namespace Chaos::Cipher::Block
{

template<typename T>
class Decryptor
{
public:
    template<typename OutputIt, typename InputIt>
    void DecryptBlock(OutputIt outBegin, OutputIt outEnd,
                      InputIt inBegin, InputIt inEnd) const
    {
        Impl().DecryptBlock(outBegin, outEnd, inBegin, inEnd);
    }

    template<typename Block>
    auto DecryptBlock(Block block) const
    {
        return Impl().DecryptBlock(block);
    }

    auto GetBlockSize() const
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
