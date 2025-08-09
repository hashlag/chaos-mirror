#ifndef CHAOS_HASHING_HASH_HPP
#define CHAOS_HASHING_HASH_HPP

#include <string>

namespace Chaos::Hashing
{

template<typename T>
class Hash
{
public:
    auto GetRawDigest() const
    {
        return static_cast<const T &>(*this).GetRawDigest();
    }

    std::string ToHexString() const
    {
        return static_cast<const T &>(*this).ToHexString();
    }
};

} // namespace Chaos::Hashing

#endif
