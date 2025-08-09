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
        static_cast<T &>(*this).Update(begin, end);
    }

    auto Finish()
    {
        return static_cast<T &>(*this).Finish();
    }
};

} // namespace Chaos::Hashing

#endif
