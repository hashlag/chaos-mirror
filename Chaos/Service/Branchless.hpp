#ifndef CHAOS_SERVICE_BRANCHLESS_HPP
#define CHAOS_SERVICE_BRANCHLESS_HPP

#include <type_traits>
#include <climits>
#include <cstdint>

namespace Chaos::Service
{

struct Branchless
{
    static constexpr uint8_t FalseMask = 0x00;
    static constexpr uint8_t TrueMask = 0xFF;

    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt MsbMask(InUInt in) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);

        constexpr uint8_t shift = (sizeof(InUInt) * CHAR_BIT) - 1;
        return static_cast<OutUInt>(0) - (in >> shift);
    }

    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt Lt(InUInt lhs, InUInt rhs) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);
        static_assert(sizeof(InUInt) <= sizeof(uint64_t));

        const uint64_t lhsEx = lhs;
        const uint64_t rhsEx = rhs;

        return MsbMask<OutUInt>(lhsEx ^ ((lhsEx ^ rhsEx) | ((lhsEx - rhsEx) ^ lhsEx)));
    }

    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt IsZero(InUInt in) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);
        static_assert(sizeof(InUInt) <= sizeof(uint64_t));

        const uint64_t inEx = in;

        return MsbMask<OutUInt>(~inEx & (inEx - 1U));
    }

    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt Eq(InUInt lhs, InUInt rhs) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);

        return IsZero<OutUInt, InUInt>(lhs ^ rhs);
    }

    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt Ge(InUInt lhs, InUInt rhs) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);

        return ~Lt<OutUInt>(lhs, rhs);
    }

    template<typename OutUInt, typename InUInt>
    static constexpr OutUInt Gt(InUInt lhs, InUInt rhs) noexcept
    {
        static_assert(std::is_unsigned_v<OutUInt> &&
                      std::is_unsigned_v<InUInt>);

        return Lt<OutUInt>(rhs, lhs);
    }

    template<typename UInt>
    static constexpr UInt Sel(UInt mask, UInt onTrue, UInt onFalse) noexcept
    {
        static_assert(std::is_unsigned_v<UInt>);

        return (mask & onTrue) | (~mask & onFalse);
    }
};

} // namespace Chaos::Service

#endif // CHAOS_SERVICE_BRANCHLESS_HPP
