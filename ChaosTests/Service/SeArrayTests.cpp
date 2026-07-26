#include <gtest/gtest.h>
#include <cstdint>
#include <iterator>
#include <cstddef>

#include "Service/SeArray.hpp"

using namespace Chaos::Service;

TEST(SeArrayTests, InitializationTest)
{
    {
        SeArray<int64_t, 200> arr;

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            ASSERT_EQ(0, arr[i]);
        }
    }

    {
        SeArray<uint32_t, 333> arr;

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            ASSERT_EQ(0, arr[i]);
        }
    }

    {
        SeArray<char, 512> arr;

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            ASSERT_EQ(0, arr[i]);
        }
    }
}

TEST(SeArrayTests, EraseTest)
{
    {
        SeArray<int64_t, 200> arr;

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            arr[i] = 1;
        }

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            ASSERT_EQ(1, arr[i]);
        }

        arr.Erase();

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            ASSERT_EQ(0, arr[i]);
        }
    }

    {
        SeArray<uint32_t, 333> arr;

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            arr[i] = 15;
        }

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            ASSERT_EQ(15, arr[i]);
        }

        arr.Erase();

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            ASSERT_EQ(0, arr[i]);
        }
    }

    {
        SeArray<char, 512> arr;

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            arr[i] = -1;
        }

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            ASSERT_EQ(-1, arr[i]);
        }

        arr.Erase();

        for (size_t i = 0; i < arr.Size(); ++i)
        {
            ASSERT_EQ(0, arr[i]);
        }
    }
}

TEST(SeArrayTests, SubscriptOperatorTest)
{
    SeArray<int32_t, 20> arr;

    arr[0] = 10;
    ASSERT_EQ(10, arr[0]);

    arr[0] = 7;
    ASSERT_EQ(7, arr[0]);

    arr[arr.Size() - 1] = 99;
    ASSERT_EQ(99, arr[arr.Size() - 1]);

    for (int32_t i = 0; i < arr.Size(); ++i)
    {
        arr[i] = i;
    }

    for (int32_t i = 0; i < arr.Size(); ++i)
    {
        ASSERT_EQ(i, arr[i]);
    }

    const SeArray<int32_t, 20> & arrRef = arr;

    for (int32_t i = 0; i < arrRef.Size(); ++i)
    {
        ASSERT_EQ(i, arrRef[i]);
    }
}

TEST(SeArrayTests, IteratorsTest)
{
    SeArray<int32_t, 20> arr;

    ASSERT_EQ(arr.Size(), std::distance(arr.Begin(), arr.End()));

    for (auto it = arr.Begin(); it != arr.End(); ++it)
    {
        ASSERT_EQ(0, *it);
    }

    {
        int32_t counter = 0;

        for (auto it = arr.Begin(); it != arr.End(); ++it)
        {
            *it = counter++;
        }

        counter = 0;

        for (auto it = arr.Begin(); it != arr.End(); ++it)
        {
            ASSERT_EQ(counter++, *it);
        }
    }

    {
        int32_t counter = 0;

        for (auto it = arr.Begin(); it != arr.End(); ++it)
        {
            *it = arr.Size() - 1 - counter++;
        }

        counter = 0;

        for (auto it = std::make_reverse_iterator(arr.End());
             it != std::make_reverse_iterator(arr.Begin()); ++it)
        {
            ASSERT_EQ(counter++, *it);
        }
    }

    {
        int32_t counter = 0;

        for (auto it = arr.Begin(); it != arr.End(); ++it)
        {
            *it = counter++;
        }

        counter = 0;
        const SeArray<int32_t, 20> & arrRef = arr;

        for (auto it = arrRef.Begin(); it != arrRef.End(); ++it)
        {
            ASSERT_EQ(counter++, *it);
        }
    }
}

TEST(SeArrayTests, SizeTest)
{
    {
        constexpr size_t SIZE = 10;

        SeArray<int32_t, SIZE> arr;
        ASSERT_EQ(SIZE, arr.Size());
    }

    {
        constexpr size_t SIZE = 20;

        SeArray<int32_t, SIZE> arr;
        ASSERT_EQ(SIZE, arr.Size());
    }

    {
        constexpr size_t SIZE = 237;

        SeArray<int32_t, SIZE> arr;
        ASSERT_EQ(SIZE, arr.Size());
    }

    {
        constexpr size_t SIZE = 100;

        SeArray<int32_t, SIZE> arr;
        ASSERT_EQ(SIZE, arr.Size());

        arr.Erase();

        ASSERT_EQ(SIZE, arr.Size());
    }
}

TEST(SeArrayTests, FillTest)
{
    SeArray<int32_t, 111> arr;

    for (size_t i = 0; i < arr.Size(); ++i)
    {
        ASSERT_EQ(0, arr[i]);
    }

    arr.Fill(112);

    for (size_t i = 0; i < arr.Size(); ++i)
    {
        ASSERT_EQ(112, arr[i]);
    }

    arr.Fill(-3);

    for (size_t i = 0; i < arr.Size(); ++i)
    {
        ASSERT_EQ(-3, arr[i]);
    }
}

TEST(SeArrayTests, CopyAssignTest)
{
    {
        SeArray<uint8_t, 2> arr1;

        SeArray<uint8_t, 2> arr2;
        arr2[0] = 0xaa;
        arr2[1] = 0xbb;

        arr1 = arr2;

        ASSERT_EQ(0xaa, arr1[0]);
        ASSERT_EQ(0xbb, arr1[1]);
    }

    {
        SeArray<int32_t, 5> arr1;
        arr1[0] = 0x33;
        arr1[1] = 0x44;
        arr1[2] = 0x55;
        arr1[3] = 0x66;
        arr1[4] = 0x77;

        SeArray<int32_t, 5> arr2;

        arr1 = arr2;

        ASSERT_EQ(0, arr1[0]);
        ASSERT_EQ(0, arr1[1]);
        ASSERT_EQ(0, arr1[2]);
        ASSERT_EQ(0, arr1[3]);
        ASSERT_EQ(0, arr1[4]);
    }
}
