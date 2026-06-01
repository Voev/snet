# Add benchmark executable
add_executable(cert_cache_benchmark
    cert_cache_benchmark.cpp
)

target_link_libraries(cert_cache_benchmark
    benchmark::benchmark
    benchmark::benchmark_main
    OpenSSL::Crypto
    snet_crypto
    snet_pki
)

target_compile_options(cert_cache_benchmark PRIVATE
    -O3
    -march=native
    -pthread
)