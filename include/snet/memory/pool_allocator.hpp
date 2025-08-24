#pragma once
#include <memory>
#include <vector>
#include <iostream>

template <typename T>
class PoolAllocator
{
private:
    struct MemoryBlock
    {
        T* memory;
        std::size_t size;
        std::size_t used;
    };

    std::vector<MemoryBlock> blocks;
    std::size_t block_size;

public:
    using value_type = T;

    explicit PoolAllocator(std::size_t initial_block_size = 1024)
        : block_size(initial_block_size)
    {
        allocate_block(block_size);
    }

    ~PoolAllocator()
    {
        for (auto& block : blocks)
        {
            std::free(block.memory);
        }
    }

    T* allocate(std::size_t n)
    {
        // Ищем блок с достаточным количеством свободной памяти
        for (auto& block : blocks)
        {
            if (block.used + n <= block.size)
            {
                T* ptr = block.memory + block.used;
                block.used += n;
                return ptr;
            }
        }

        // Если не нашли - выделяем новый блок
        std::size_t new_block_size = std::max(n, block_size);
        allocate_block(new_block_size);
        blocks.back().used = n;
        return blocks.back().memory;
    }

    void deallocate(T*, std::size_t) noexcept
    {
        // Простая реализация - не освобождаем память до деструктора
        // В реальном аллокаторе нужно реализовать управление памятью
    }

private:
    void allocate_block(std::size_t size)
    {
        MemoryBlock block;
        block.memory = static_cast<T*>(std::malloc(size * sizeof(T)));
        if (!block.memory)
        {
            throw std::bad_alloc();
        }
        block.size = size;
        block.used = 0;
        blocks.push_back(block);
    }
};

template <typename T, typename U>
bool operator==(const PoolAllocator<T>&, const PoolAllocator<U>&)
{
    return true;
}

template <typename T, typename U>
bool operator!=(const PoolAllocator<T>&, const PoolAllocator<U>&)
{
    return false;
}