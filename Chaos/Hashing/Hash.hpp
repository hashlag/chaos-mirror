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
        return Impl().GetRawDigest();
    }

    std::string ToHexString() const
    {
        return Impl().ToHexString();
    }

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

} // namespace Chaos::Hashing

#endif
