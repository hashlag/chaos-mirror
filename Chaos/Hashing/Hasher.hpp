#ifndef CHAOS_HASHING_HASHER_HPP
#define CHAOS_HASHING_HASHER_HPP

namespace Chaos::Hashing
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

} // namespace Chaos::Hashing

#endif
