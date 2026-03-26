#pragma once

#include <iterator>
#include <type_traits>

namespace snet
{

struct IntrusiveNode
{
    IntrusiveNode* next;
    IntrusiveNode* prev;

    IntrusiveNode()
        : next(this)
        , prev(this)
    {
    }

    bool is_linked() const
    {
        return next != this;
    }

    void unlink()
    {
        if (is_linked())
        {
            next->prev = prev;
            prev->next = next;
            next = prev = this;
        }
    }
};

template <typename T, IntrusiveNode T::* NodeField>
struct IntrusiveListTraits
{
    static IntrusiveNode* to_node(T* obj)
    {
        return &(obj->*NodeField);
    }

    static T* from_node(IntrusiveNode* node)
    {
        static_assert(std::is_standard_layout<T>::value, "T must be standard-layout");
        return reinterpret_cast<T*>(reinterpret_cast<char*>(node) -
                                    reinterpret_cast<size_t>(&(static_cast<T*>(nullptr)->*NodeField)));
    }
};

template <typename T, IntrusiveNode T::* NodeField>
class IntrusiveList
{
private:
    IntrusiveNode head_;
    size_t size_;

    using Traits = IntrusiveListTraits<T, NodeField>;

    IntrusiveNode* to_node(T* obj) const
    {
        return Traits::to_node(obj);
    }
    T* from_node(IntrusiveNode* node) const
    {
        return Traits::from_node(node);
    }

public:
    IntrusiveList()
        : head_()
        , size_(0)
    {
    }

    // Добавить элемент в начало
    void push_front(T* obj)
    {
        IntrusiveNode* node = to_node(obj);
        node->next = head_.next;
        node->prev = &head_;
        head_.next->prev = node;
        head_.next = node;
        ++size_;
    }

    // Добавить элемент в конец
    void push_back(T* obj)
    {
        IntrusiveNode* node = to_node(obj);
        node->prev = head_.prev;
        node->next = &head_;
        head_.prev->next = node;
        head_.prev = node;
        ++size_;
    }

    // Извлечь элемент из начала
    T* pop_front()
    {
        if (empty())
            return nullptr;
        IntrusiveNode* node = head_.next;
        node->unlink();
        --size_;
        return from_node(node);
    }

    // Извлечь элемент из конца
    T* pop_back()
    {
        if (empty())
            return nullptr;
        IntrusiveNode* node = head_.prev;
        node->unlink();
        --size_;
        return from_node(node);
    }

    // Удалить элемент из списка (если он там есть)
    void remove(T* obj)
    {
        IntrusiveNode* node = to_node(obj);
        if (node->is_linked())
        {
            node->unlink();
            --size_;
        }
    }

    // Проверить, пуст ли список
    bool empty() const
    {
        return size_ == 0;
    }

    // Получить размер списка
    size_t size() const
    {
        return size_;
    }

    // Очистить список (удалить все элементы, но не освобождать память)
    void clear()
    {
        while (!empty())
        {
            pop_front();
        }
    }

    // Получить первый элемент (без удаления)
    T* front() const
    {
        if (empty())
            return nullptr;
        return from_node(head_.next);
    }

    // Получить последний элемент (без удаления)
    T* back() const
    {
        if (empty())
            return nullptr;
        return from_node(head_.prev);
    }

    // Переместить все элементы из другого списка в конец текущего
    void splice(IntrusiveList& other)
    {
        if (other.empty())
            return;

        // Связываем конец текущего списка с началом другого
        head_.prev->next = other.head_.next;
        other.head_.next->prev = head_.prev;
        head_.prev = other.head_.prev;
        other.head_.prev->next = &head_;

        // Очищаем другой список
        other.head_.next = other.head_.prev = &other.head_;
        size_ += other.size_;
        other.size_ = 0;
    }

    // Итератор для обхода (простой, только вперёд)
    class Iterator
    {
    private:
        IntrusiveNode* current_;
        const IntrusiveList* list_;

    public:
        Iterator(IntrusiveNode* node, const IntrusiveList* list)
            : current_(node)
            , list_(list)
        {
        }

        Iterator& operator++()
        {
            current_ = current_->next;
            return *this;
        }

        bool operator!=(const Iterator& other) const
        {
            return current_ != other.current_;
        }

        T* operator*() const
        {
            return list_->from_node(current_);
        }
    };

    Iterator begin() const
    {
        return Iterator(head_.next, this);
    }
    Iterator end() const
    {
        return Iterator(const_cast<IntrusiveNode*>(&head_), this);
    }
};

}