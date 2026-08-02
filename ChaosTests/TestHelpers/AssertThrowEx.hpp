#ifndef CHAOSTESTS_TESTHELPERS_ASSERTTHROWEX_HPP
#define CHAOSTESTS_TESTHELPERS_ASSERTTHROWEX_HPP

#include <gtest/gtest.h>

#define ASSERT_THROW_EX(statement, expected_exception_type, assertions)                        \
    do                                                                                         \
    {                                                                                          \
        bool ASSERT_THROW_EX_expectedExceptionThrown = false;                                  \
                                                                                               \
        try                                                                                    \
        {                                                                                      \
            statement;                                                                         \
        }                                                                                      \
        catch (const expected_exception_type & ex)                                             \
        {                                                                                      \
            ASSERT_THROW_EX_expectedExceptionThrown = true;                                    \
            assertions;                                                                        \
        }                                                                                      \
        catch (...)                                                                            \
        {                                                                                      \
            FAIL() << "Expected: " << #statement << " throws an exception of type "            \
                   << #expected_exception_type << ".\n  Actual: it throws a different type.";  \
        }                                                                                      \
                                                                                               \
        if (!ASSERT_THROW_EX_expectedExceptionThrown)                                          \
        {                                                                                      \
            FAIL() << "Expected: " << #statement << " throws an exception of type "            \
                   << #expected_exception_type << ".\n  Actual: it throws nothing.";           \
        }                                                                                      \
    }                                                                                          \
    while (false)

#endif // CHAOSTESTS_TESTHELPERS_ASSERTTHROWEX_HPP
