#ifndef CHAOS_SERVICE_SEARRAY_HPP
#define CHAOS_SERVICE_SEARRAY_HPP

#include <array>
#include <type_traits>

namespace Chaos::Service
{

template<typename T, size_t S,
         typename = std::enable_if_t<std::is_integral_v<T>>>
class SeArray
{
public:
    SeArray()
    {
        Storage_.fill(0);
    }

    SeArray(const SeArray & other) = delete;
    SeArray(SeArray && other) = delete;

    SeArray & operator=(const SeArray & other) = delete;
    SeArray & operator=(SeArray && other) = delete;

    ~SeArray()
    {
        EraseImpl();
    }

    T & operator[](size_t pos)
    {
        return Storage_[pos];
    }

    const T & operator[](size_t pos) const
    {
        return Storage_[pos];
    }

    T * Begin() noexcept
    {
        return Storage_.data();
    }

    const T * Begin() const noexcept 
    {
        return Storage_.data();
    }

    T * End() noexcept
    {
        return Storage_.data() + Storage_.size();
    }

    const T * End() const noexcept
    {
        return Storage_.data() + Storage_.size();
    }

    constexpr size_t Size() const noexcept
    {
        return Storage_.size();
    }

    void Fill(const T & value)
    {
        Storage_.fill(value);
    }

    void Erase()
    {
        EraseImpl();
    }

private:
    std::array<T, S> Storage_;

    void EraseImpl()
    {
        volatile T * ptr = Storage_.data();

        for (size_t i = 0; i < Storage_.size(); ++i)
        {
            *ptr++ = 0;
        }
    }
};

} // namespace Chaos::Service

#endif // CHAOS_SERVICE_SEARRAY_HPP
