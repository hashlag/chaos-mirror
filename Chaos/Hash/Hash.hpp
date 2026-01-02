#ifndef CHAOS_HASH_HASH_HPP
#define CHAOS_HASH_HASH_HPP

#include <string>

namespace Chaos::Hash
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

} // namespace Chaos::Hash

#endif // CHAOS_HASH_HASH_HPP
