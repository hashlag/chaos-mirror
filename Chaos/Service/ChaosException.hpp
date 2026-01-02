#ifndef CHAOS_SERVICE_CHAOSEXCEPTION_HPP
#define CHAOS_SERVICE_CHAOSEXCEPTION_HPP

#include <string>

namespace Chaos::Service
{

class ChaosException
{
public:
    ChaosException(std::string && message)
        : Message_(std::move(message))
    { }

    ChaosException(const std::string & message)
        : Message_(message)
    { }

    const std::string & GetMessage() const
    {
        return Message_;
    }

private:
    std::string Message_;
};

} // namespace Chaos::Service

#endif // CHAOS_SERVICE_CHAOSEXCEPTION_HPP
