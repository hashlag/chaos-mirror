#ifndef CHAOS_CIPHER_BLOCK_BLOCKADAPTER_HPP
#define CHAOS_CIPHER_BLOCK_BLOCKADAPTER_HPP

#include <cstdint>
#include <vector>

namespace Chaos::Cipher::Block
{

template<typename ModeT>
class BlockAdapter
{
public:
    class Key
    {
        friend class BlockAdapter;
    public:
        template<typename InputIt>
        Key(InputIt keyBegin, InputIt keyEnd)
            : Key_(keyBegin, keyEnd)
        { }

        template<typename Byte>
        Key(const std::vector<Byte> & key)
            : Key_(key.cbegin(), key.cend())
        { }

    private:
        ModeT::Cipher::Key Key_;
    };

    template<typename Byte>
    static std::vector<Byte> Encrypt(const Key & key, const std::vector<Byte> & plaintext)
    {
        typename ModeT::Encryptor encryptor(key.Key_);

        std::vector<Byte> result;
        const uint64_t maxResultSize = encryptor.PredictMaxUpdateOutput(plaintext.size()) +
                                       encryptor.PredictMaxFinishOutput();
        result.resize(maxResultSize);

        uint64_t written = encryptor.Update(result.begin(), result.end(),
                                            plaintext.begin(), plaintext.end());
        written += encryptor.Finish(result.begin() + written, result.end());

        result.resize(written);
        return result;
    }
};

} // namespace Chaos::Cipher::Block

#endif // CHAOS_CIPHER_BLOCK_BLOCKADAPTER_HPP
