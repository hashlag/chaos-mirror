#ifndef CHAOS_PADDING_PADDER_HPP
#define CHAOS_PADDING_PADDER_HPP

namespace Chaos::Padding
{

template<typename T>
class Padder
{
public:
    template<typename OutputIt>
    void Pad(OutputIt begin, OutputIt end) const
    {
        Impl().Pad(begin, end);
    }

protected:
    Padder() = default;

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

} // namespace Chaos::Padding

#endif // CHAOS_PADDING_PADDER_HPP
