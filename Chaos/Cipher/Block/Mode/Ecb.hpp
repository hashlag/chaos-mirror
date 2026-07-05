#ifndef CHAOS_CIPHER_BLOCK_MODE_ECB_HPP
#define CHAOS_CIPHER_BLOCK_MODE_ECB_HPP

#include <cstddef>
#include <cstdint>

#include "Service/ChaosException.hpp"
#include "Service/SeArray.hpp"

namespace Chaos::Cipher::Block::Mode
{

template<typename CipherT, typename PadderT>
class EcbMode
{
public:
    class Encryptor
    {
    public:
        Encryptor(const typename CipherT::Key & key)
            : Encryptor_(key)
            , BlockBytesPacked_(0)
        { }

        static constexpr uint64_t PredictMaxUpdateOutput(uint64_t in)
        {
            return in + CipherT::BlockSize - 1;
        }

        static constexpr uint64_t PredictMaxFinishOutput()
        {
            return CipherT::BlockSize;
        }

        template<typename OutputIt, typename InputIt>
        uint64_t Update(OutputIt outBegin, OutputIt outEnd,
                        InputIt inBegin, InputIt inEnd)
        {
            return UpdateImpl(outBegin, outEnd, inBegin, inEnd);
        }

        template<typename OutputIt>
        uint64_t Finish(OutputIt outBegin, OutputIt outEnd)
        {
            PadderT::Pad(Block_.Begin() + BlockBytesPacked_, Block_.End());

            Encryptor_.EncryptBlock(EncryptedBlock_.Begin(), EncryptedBlock_.End(),
                                    Block_.Begin(), Block_.End());
            EnsureCopy(outBegin, outEnd, EncryptedBlock_.Begin(), EncryptedBlock_.End());

            return CipherT::BlockSize;
        }

    private:
        typename CipherT::Encryptor Encryptor_;

        uint64_t BlockBytesPacked_;
        Service::SeArray<uint8_t, CipherT::BlockSize> Block_;

        Service::SeArray<uint8_t, CipherT::BlockSize> EncryptedBlock_;

        template<typename OutputIt, typename InputIt>
        static OutputIt EnsureCopy(OutputIt outBegin, OutputIt outEnd,
                                   InputIt inBegin, InputIt inEnd)
        {
            OutputIt out = outBegin;
            InputIt in = inBegin;

            for (; out != outEnd && in != inEnd; ++out, ++in)
            {
                *out = *in;
            }

            if (out == outEnd && in != inEnd)
            {
                throw Service::ChaosException("EcbMode<>::Encryptor: insufficient output "
                                              "buffer size");
            }

            return out;
        }

        template<typename OutputIt, typename InputIt>
        uint64_t UpdateImpl(OutputIt outBegin, OutputIt outEnd,
                            InputIt inBegin, InputIt inEnd)
        {
            uint64_t written = 0;
            OutputIt out = outBegin;

            for (InputIt in = inBegin; in != inEnd; ++in)
            {
                Block_[BlockBytesPacked_++] = *in;

                if (BlockBytesPacked_ == Block_.Size())
                {
                    BlockBytesPacked_ = 0;

                    Encryptor_.EncryptBlock(EncryptedBlock_.Begin(), EncryptedBlock_.End(),
                                            Block_.Begin(), Block_.End());
                    out = EnsureCopy(out, outEnd, EncryptedBlock_.Begin(), EncryptedBlock_.End());

                    written += CipherT::BlockSize;
                }
            }

            return written;
        }
    };
};

} // namespace Chaos::Cipher::Block::Mode

#endif // CHAOS_CIPHER_BLOCK_MODE_ECB_HPP
