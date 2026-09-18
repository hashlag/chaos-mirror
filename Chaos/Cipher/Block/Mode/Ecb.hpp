#ifndef CHAOS_CIPHER_BLOCK_MODE_ECB_HPP
#define CHAOS_CIPHER_BLOCK_MODE_ECB_HPP

#include <cstddef>
#include <cstdint>

#include "Cipher/Block/BlockCipher.hpp"
#include "Padding/Padder.hpp"
#include "Service/ChaosException.hpp"
#include "Service/SeArray.hpp"

namespace Chaos::Cipher::Block::Mode
{

template<Cipher::Block::BlockCipher CipherT, Padding::Padder PadderT>
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

        Service::SeArray<uint8_t, CipherT::BlockSize> EncryptedBlock_;

        Service::SeArray<uint8_t, CipherT::BlockSize> Block_;
        uint64_t BlockBytesPacked_;

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

    class Decryptor
    {
    public:
        Decryptor(const typename CipherT::Key & key)
            : Decryptor_(key)
            , BlockBytesPacked_(0)
            , LastBlockSaved_(false)
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
            if (BlockBytesPacked_ != 0)
            {
                throw Service::ChaosException("EcbMode<>::Decryptor: ciphertext size "
                                              "is not a multiple of the algorithm's "
                                              "block size");
            }

            if (!LastBlockSaved_)
            {
                return 0;
            }

            auto unpadResult = PadderT::ComputeUnpad(LastBlock_.Begin(),
                                                     LastBlock_.End());
            if (!unpadResult.IsOkay_)
            {
                throw Service::ChaosException("EcbMode<>::Decryptor: invalid ciphertext");
            }

            const uint64_t lastChunkSize = CipherT::BlockSize - unpadResult.PadSize_;

            EnsureCopy(outBegin, outEnd,
                       LastBlock_.Begin(),
                       LastBlock_.Begin() + lastChunkSize);

            return lastChunkSize;
        }

    private:
        using BlockArray = Service::SeArray<uint8_t, CipherT::BlockSize>;

        typename CipherT::Decryptor Decryptor_;

        BlockArray Block_;
        BlockArray LastBlock_;

        uint64_t BlockBytesPacked_;
        bool LastBlockSaved_;

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
                throw Service::ChaosException("EcbMode<>::Decryptor: insufficient output "
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

                    if (LastBlockSaved_)
                    {
                        out = EnsureCopy(out, outEnd,
                                         LastBlock_.Begin(), LastBlock_.End());

                        written += CipherT::BlockSize;
                    }

                    Decryptor_.DecryptBlock(LastBlock_.Begin(), LastBlock_.End(),
                                            Block_.Begin(), Block_.End());
                    LastBlockSaved_ = true;
                }
            }

            return written;
        }
    };
};

} // namespace Chaos::Cipher::Block::Mode

#endif // CHAOS_CIPHER_BLOCK_MODE_ECB_HPP
