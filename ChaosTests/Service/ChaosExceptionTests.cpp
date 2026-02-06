#include <gtest/gtest.h>
#include <string>

#include "Service/ChaosException.hpp"

using namespace Chaos::Service;

TEST(ChaosExceptionTests, RvalueRefCtorTest)
{
    try
    {
        throw ChaosException("everything's alright :D");
    }
    catch (const ChaosException & ex)
    {
        ASSERT_EQ("everything's alright :D", ex.GetMessage());
    }
}

TEST(ChaosExceptionTests, ConstLvalueRefCtorTest)
{
    const std::string message = "everything's alright :D";

    try
    {
        throw ChaosException(message);
    }
    catch (const ChaosException & ex)
    {
        ASSERT_EQ("everything's alright :D", ex.GetMessage());
    }
}
