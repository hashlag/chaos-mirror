#ifndef CHAOS_SERVICE_SEARRAY_HPP
#define CHAOS_SERVICE_SEARRAY_HPP

#include <array>
#include <concepts>
#include <cstddef>
#include <utility>

namespace Chaos::Service
{

template<std::integral T, size_t S>
class SeArray
{
public:
    SeArray()
    {
        Storage_.fill(0);
    }

    SeArray(const SeArray & other) = delete;

    SeArray(SeArray && other)
    {
        Storage_ = std::move(other.Storage_);
        other.EraseImpl();
    }

    SeArray & operator=(const SeArray & other) = default;

    SeArray & operator=(SeArray && other)
    {
        if (this == &other)
        {
            return *this;
        }

        EraseImpl();
        Storage_ = std::move(other.Storage_);
        other.EraseImpl();

        return *this;
    }

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

    void Fill(const T & value)
    {
        Storage_.fill(value);
    }

    void Erase()
    {
        EraseImpl();
    }

    static constexpr size_t Size() noexcept
    {
        return S;
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
