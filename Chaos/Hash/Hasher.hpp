#ifndef CHAOS_HASH_HASHER_HPP
#define CHAOS_HASH_HASHER_HPP

namespace Chaos::Hash
{

template<typename T>
class Hasher
{
public:
    template<typename InputIt>
    void Update(InputIt begin, InputIt end)
    {
        Impl().Update(begin, end);
    }

    auto Finish()
    {
        return Impl().Finish();
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

#endif
