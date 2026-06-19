#pragma once

#include <functional>
#include <vector>
#include <exception>
#include <utility>
#include <type_traits>


/**
 * @brief Цепочка действий с автоматическим откатом при ошибке
 * 
 * Позволяет объединить несколько операций в транзакцию с гарантией,
 * что при возникновении исключения все предыдущие операции будут откачены
 * в обратном порядке.
 * 
 * @example
 * ActionChain chain;
 * Object* obj = nullptr;
 * 
 * chain.addAction(
 *     [&]() { obj = new Object(); },
 *     [&]() { delete obj; }
 * );
 * 
 * chain.addAction(
 *     [&]() { writeToFile(obj); },
 *     [&]() { removeFile("data.dat"); }
 * );
 * 
 * chain.execute();
 */
class ActionChain {
public:
    using Action = std::function<void()>;
    using Rollback = std::function<void()>;

    /**
     * @brief Структура для хранения пары "действие - откат"
     */
    struct ActionPair {
        Action forward;
        Rollback rollback;
        bool executed = false;

        ActionPair(Action fwd, Rollback rlb)
            : forward(std::move(fwd))
            , rollback(std::move(rlb))
        {}

        ActionPair(ActionPair&& other) noexcept
            : forward(std::move(other.forward))
            , rollback(std::move(other.rollback))
            , executed(other.executed)
        {}

        ActionPair& operator=(ActionPair&& other) noexcept {
            if (this != &other) {
                forward = std::move(other.forward);
                rollback = std::move(other.rollback);
                executed = other.executed;
            }
            return *this;
        }

        // Запрещаем копирование
        ActionPair(const ActionPair&) = delete;
        ActionPair& operator=(const ActionPair&) = delete;
    };

    ActionChain() = default;
    
    ~ActionChain() {
        if(!m_committed)
            rollbackAll();
    }

    // Запрещаем копирование
    ActionChain(const ActionChain&) = delete;
    ActionChain& operator=(const ActionChain&) = delete;

    // Разрешаем перемещение
    ActionChain(ActionChain&& other) noexcept
        : m_actions(std::move(other.m_actions))
        , m_committed(other.m_committed)
    {
        other.m_committed = false;
    }

    ActionChain& operator=(ActionChain&& other) noexcept {
        if (this != &other) {
            rollbackAll();
            m_actions = std::move(other.m_actions);
            m_committed = other.m_committed;
            other.m_committed = false;
        }
        return *this;
    }

    /**
     * @brief Добавить действие с функцией отката
     * 
     * @tparam Fwd Тип функции прямого действия
     * @tparam Rlb Тип функции отката
     * @param forward Функция, выполняющая основное действие
     * @param rollback Функция, откатывающая действие при ошибке
     * @return ActionChain& Ссылка на текущий объект для цепочек
     */
    template <typename Fwd, typename Rlb>
    ActionChain& addAction(Fwd&& forward, Rlb&& rollback) {
        static_assert(std::is_invocable_v<Fwd>,
            "forward must be callable with no arguments");
        static_assert(std::is_invocable_v<Rlb>,
            "rollback must be callable with no arguments");

        m_actions.emplace_back(
            std::forward<Fwd>(forward),
            std::forward<Rlb>(rollback)
        );
        return *this;
    }

    /**
     * @brief Добавить действие только с прямым ходом (без отката)
     * 
     * @tparam Fwd Тип функции прямого действия
     * @param forward Функция, выполняющая основное действие
     * @return ActionChain& Ссылка на текущий объект для цепочек
     */
    template <typename Fwd>
    ActionChain& addAction(Fwd&& forward) {
        static_assert(std::is_invocable_v<Fwd>,
            "forward must be callable with no arguments");

        m_actions.emplace_back(
            std::forward<Fwd>(forward),
            []() {} // Пустой откат
        );
        return *this;
    }

    /**
     * @brief Выполнить все добавленные действия
     * 
     * Действия выполняются последовательно. Если какое-то действие
     * выбрасывает исключение, все ранее выполненные действия
     * откатываются в обратном порядке.
     * 
     * @throw std::exception Любое исключение из действий или откатов
     */
    void execute() {
        if (m_committed) {
            return; // Уже выполнено
        }

        m_committed = true; // Временная фиксация, будет отменена при ошибке

        try {
            for (size_t i = 0; i < m_actions.size(); ++i) {
                try {
                    m_actions[i].forward();
                    m_actions[i].executed = true;
                } catch (...) {
                    // Откатываем все ранее выполненные действия
                    rollbackExecuted(i);
                    m_committed = false;
                    throw; // Перебрасываем исходное исключение
                }
            }
        } catch (...) {
            m_committed = false;
            throw;
        }
    }

    /**
     * @brief Принудительно зафиксировать цепочку (отключить автоматический откат)
     * 
     * Используйте после успешного выполнения, чтобы предотвратить
     * откат в деструкторе.
     */
    void commit() {
        m_committed = true;
    }

    /**
     * @brief Откатить все выполненные действия
     * 
     * Можно вызвать вручную для явного отката
     */
    void rollback() {
        rollbackAll();
        m_committed = false;
    }

    /**
     * @brief Проверить, зафиксирована ли цепочка
     */
    bool isCommitted() const {
        return m_committed;
    }

    /**
     * @brief Получить количество действий в цепочке
     */
    size_t size() const {
        return m_actions.size();
    }

    /**
     * @brief Очистить все действия
     */
    void clear() {
        rollbackAll();
        m_actions.clear();
        m_committed = false;
    }

private:
    std::vector<ActionPair> m_actions;
    bool m_committed = false;

    /**
     * @brief Откатить все выполненные действия в обратном порядке
     */
    void rollbackAll() noexcept {
        if (!m_actions.empty()) {
            rollbackExecuted(m_actions.size());
        }
    }

    /**
     * @brief Откатить выполненные действия до указанного индекса
     * @param untilIndex Индекс, до которого нужно откатить (не включая)
     */
    void rollbackExecuted(size_t untilIndex) noexcept {
        // Идем в обратном порядке
        for (size_t i = untilIndex; i > 0; --i) {
            size_t idx = i - 1;
            if (m_actions[idx].executed) {
                try {
                    m_actions[idx].rollback();
                    m_actions[idx].executed = false;
                } catch (...) {
                    // Логируем ошибку отката, но продолжаем
                    // Можно использовать свой логгер, если есть
                }
            }
        }
    }
};
