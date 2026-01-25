#include <benchmark/benchmark.h>
#include <cstring>

#include <Hash/Md5.hpp>

using namespace Chaos::Hash::Md5;

static const char * DATA_BEGIN
    = "All states, all powers, that have held and hold rule over men have been and are either republics or principalities.\n"
      "Principalities are either hereditary, in which the family has been long established; or they are new.\n"
      "The new are either entirely new, as was Milan to Francesco Sforza, or they are, as it were, members annexed to the hereditary state of the "
      "prince who has acquired them, as was the kingdom of Naples to that of the King of Spain.\n"
      "Such dominions thus acquired are either accustomed to live under a prince, or to live in freedom; and are acquired either by the arms of the "
      "prince himself, or of others, or else by fortune or by ability.";
static const size_t DATA_LEN = strlen(DATA_BEGIN);
static const char * DATA_END = DATA_BEGIN + DATA_LEN;

static void Md5HasherCreateComputeDeleteBench(benchmark::State & state)
{
    for (auto _ : state)
    {
        Md5Hasher hasher;
        hasher.Update(DATA_BEGIN, DATA_END);
        Md5Hash result = hasher.Finish();

        benchmark::DoNotOptimize(result);
    }
}

BENCHMARK(Md5HasherCreateComputeDeleteBench);

static void Md5HasherReuseBench(benchmark::State & state)
{
    Md5Hasher hasher;

    for (auto _ : state)
    {
        hasher.Reset();
        hasher.Update(DATA_BEGIN, DATA_END);
        Md5Hash result = hasher.Finish();

        benchmark::DoNotOptimize(result);
    }
}

BENCHMARK(Md5HasherReuseBench);

static void Md5HasherPartialUpdate100Bench(benchmark::State & state)
{
    for (auto _ : state)
    {
        Md5Hasher hasher;

        for (int i = 0; i < 100; ++i)
        {
            hasher.Update(DATA_BEGIN, DATA_END);
        }

        Md5Hash result = hasher.Finish();

        benchmark::DoNotOptimize(result);
    }
}

BENCHMARK(Md5HasherPartialUpdate100Bench);
