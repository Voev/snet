#include <benchmark/benchmark.h>
#include <thread>
#include <random>
#include <future>
#include <snet/pki/cert_cache.hpp>

namespace snet::pki
{

static crypto::X509CertPtr createTestCert(uint64_t id)
{
    (void)id;
    return nullptr;
}

static std::string certToString(X509Cert* cert)
{
    return "test_cert_" + std::to_string(reinterpret_cast<uintptr_t>(cert));
}

class CertCacheBenchmark : public benchmark::Fixture
{
protected:
    void SetUp(const benchmark::State& st) override
    {
        CacheConfig config;
        config.workerThreads = std::min<size_t>(4, std::thread::hardware_concurrency());
        config.l2Ttl = std::chrono::seconds(60);
        config.l1Ttl = std::chrono::seconds(3600);

        cache = std::make_unique<CertCache>(config);

        for (int i = 0; i < st.range(0); ++i)
        {
            testCerts.push_back(createTestCert(i));
            testPolicies.push_back("policy_" + std::to_string(i % 10));
            testCertsStr.push_back(certToString(testCerts.back().get()));
        }
    }

    void TearDown(const benchmark::State&) override
    {
        cache.reset();
        testCerts.clear();
        testPolicies.clear();
        testCertsStr.clear();
    }

    std::unique_ptr<CertCache> cache;
    std::vector<crypto::X509CertPtr> testCerts;
    std::vector<std::string> testPolicies;
    std::vector<std::string> testCertsStr;
};

BENCHMARK_DEFINE_F(CertCacheBenchmark, SequentialGet)(benchmark::State& state)
{
    size_t idx = 0;
    for (auto _ : state)
    {
        auto cert = cache->get(testCerts[idx % testCerts.size()].get(), testPolicies[idx % testPolicies.size()],
                               testCertsStr[idx % testCertsStr.size()]);
        benchmark::DoNotOptimize(cert);
        ++idx;
    }
}

BENCHMARK_DEFINE_F(CertCacheBenchmark, ParallelGet)(benchmark::State& state)
{
    const int numThreads = state.range(1);

    for (auto _ : state)
    {
        std::vector<std::future<void>> futures;

        for (int t = 0; t < numThreads; ++t)
        {
            futures.push_back(std::async(std::launch::async,
                                         [this, &state]()
                                         {
                                             size_t idx = 0;
                                             auto start = std::chrono::steady_clock::now();

                                             while (std::chrono::steady_clock::now() - start < std::chrono::seconds(1))
                                             {
                                                 auto cert = cache->get(testCerts[idx % testCerts.size()].get(),
                                                                        testPolicies[idx % testPolicies.size()],
                                                                        testCertsStr[idx % testCertsStr.size()]);
                                                 benchmark::DoNotOptimize(cert);
                                                 ++idx;
                                             }
                                         }));
        }

        for (auto& f : futures)
        {
            f.wait();
        }
    }
}

BENCHMARK_DEFINE_F(CertCacheBenchmark, WorkingSetSize)(benchmark::State& state)
{
    size_t workingSetSize = state.range(0);
    size_t idx = 0;

    for (auto _ : state)
    {
        auto cert = cache->get(testCerts[idx % workingSetSize].get(), testPolicies[idx % testPolicies.size()],
                               testCertsStr[idx % testCertsStr.size()]);
        benchmark::DoNotOptimize(cert);
        ++idx;
    }
}

BENCHMARK_DEFINE_F(CertCacheBenchmark, HitRatio)(benchmark::State& state)
{
    size_t idx = 0;
    size_t hits = 0;
    size_t misses = 0;

    for (auto _ : state)
    {
        auto cert = cache->get(testCerts[idx % testCerts.size()].get(), testPolicies[idx % testPolicies.size()],
                               testCertsStr[idx % testCertsStr.size()]);

        if (cert)
            hits++;
        else
            misses++;

        ++idx;

        if (idx % 1000 == 0)
        {
            state.SetLabel(("Hit ratio: " + std::to_string(100.0 * hits / (hits + misses)) + "%").c_str());
        }
    }
}

BENCHMARK_DEFINE_F(CertCacheBenchmark, WarmCache)(benchmark::State& state)
{
    for (size_t i = 0; i < testCerts.size(); ++i)
    {
        cache->get(testCerts[i].get(), testPolicies[i % testPolicies.size()], testCertsStr[i % testCertsStr.size()]);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    size_t idx = 0;
    for (auto _ : state)
    {
        auto cert = cache->get(testCerts[idx % testCerts.size()].get(), testPolicies[idx % testPolicies.size()],
                               testCertsStr[idx % testCertsStr.size()]);
        benchmark::DoNotOptimize(cert);
        ++idx;
    }
}

BENCHMARK_DEFINE_F(CertCacheBenchmark, BlockingGet)(benchmark::State& state)
{
    std::chrono::milliseconds timeout(state.range(1));

    for (auto _ : state)
    {
        auto cert = cache->getBlocking(testCerts[0].get(), testPolicies[0], testCertsStr[0], timeout);
        benchmark::DoNotOptimize(cert);
    }
}

BENCHMARK_REGISTER_F(CertCacheBenchmark, SequentialGet)
    ->Args({100})
    ->Args({1000})
    ->Args({10000})
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_REGISTER_F(CertCacheBenchmark, ParallelGet)
    ->Args({1000, 2})
    ->Args({1000, 4})
    ->Args({1000, 8})
    ->Args({1000, 16})
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_REGISTER_F(CertCacheBenchmark, WorkingSetSize)
    ->Arg(10)
    ->Arg(100)
    ->Arg(1000)
    ->Arg(10000)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_REGISTER_F(CertCacheBenchmark, HitRatio)->Arg(1000)->Iterations(10000)->Unit(benchmark::kMicrosecond);

BENCHMARK_REGISTER_F(CertCacheBenchmark, WarmCache)->Arg(100)->Arg(1000)->Unit(benchmark::kNanosecond);

BENCHMARK_REGISTER_F(CertCacheBenchmark, BlockingGet)
    ->Args({1, 100})
    ->Args({1, 500})
    ->Args({1, 1000})
    ->Unit(benchmark::kMillisecond);

} // namespace snet::pki

BENCHMARK_MAIN();