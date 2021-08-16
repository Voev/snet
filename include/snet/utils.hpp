#pragma once
#include <chrono>
#include <thread>

inline void SleepMs(const int x)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(x));
}