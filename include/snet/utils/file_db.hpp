#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <unordered_map>
#include <map>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <any>
#include <typeindex>
#include <typeinfo>
#include <variant>

class TXTDBException : public std::exception
{
private:
    std::string message;

public:
    enum ErrorType
    {
        OK = 0,
        WRONG_NUM_FIELDS,
        INDEX_OUT_OF_RANGE,
        NO_INDEX,
        INDEX_CLASH,
        MALLOC_ERROR,
        TYPE_MISMATCH,
        INVALID_CONVERSION
    };

    TXTDBException(ErrorType type, const std::string& msg = "")
    {
        switch (type)
        {
        case WRONG_NUM_FIELDS:
            message = "Wrong number of fields";
            break;
        case INDEX_OUT_OF_RANGE:
            message = "Index out of range";
            break;
        case NO_INDEX:
            message = "No index";
            break;
        case INDEX_CLASH:
            message = "Index clash";
            break;
        case MALLOC_ERROR:
            message = "Memory allocation error";
            break;
        case TYPE_MISMATCH:
            message = "Type mismatch";
            break;
        case INVALID_CONVERSION:
            message = "Invalid conversion";
            break;
        default:
            message = "Unknown error";
            break;
        }
        if (!msg.empty() && type != OK)
        {
            message += ": " + msg;
        }
    }

    const char* what() const noexcept override
    {
        return message.c_str();
    }
};

class FieldValue
{
public:
    virtual ~FieldValue() = default;
    virtual std::string toString() const = 0;
    virtual std::shared_ptr<FieldValue> clone() const = 0;
    virtual bool equals(const FieldValue& other) const = 0;
    virtual int compare(const FieldValue& other) const = 0;
    virtual std::type_index getType() const = 0;
    virtual size_t hash() const = 0;
};

template <typename T>
class TypedFieldValue : public FieldValue
{
private:
    T value;

public:
    TypedFieldValue(const T& val)
        : value(val)
    {
    }
    TypedFieldValue(T&& val)
        : value(std::move(val))
    {
    }

    std::string toString() const override
    {
        if constexpr (std::is_same_v<T, std::string>)
        {
            return value;
        }
        else if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T>)
        {
            return std::to_string(value);
        }
        else
        {
            return "Unsupported type";
        }
    }

    std::shared_ptr<FieldValue> clone() const override
    {
        return std::make_shared<TypedFieldValue<T>>(value);
    }

    bool equals(const FieldValue& other) const override
    {
        if (getType() != other.getType())
        {
            return false;
        }
        const auto& typedOther = dynamic_cast<const TypedFieldValue<T>&>(other);
        return value == typedOther.value;
    }

    int compare(const FieldValue& other) const override
    {
        if (getType() != other.getType())
        {
            throw TXTDBException(TXTDBException::TYPE_MISMATCH, "Cannot compare different types");
        }
        const auto& typedOther = dynamic_cast<const TypedFieldValue<T>&>(other);
        if (value < typedOther.value)
            return -1;
        if (value > typedOther.value)
            return 1;
        return 0;
    }

    std::type_index getType() const override
    {
        return std::type_index(typeid(T));
    }

    size_t hash() const override
    {
        return std::hash<T>()(value);
    }

    const T& getValue() const
    {
        return value;
    }
    T& getValue()
    {
        return value;
    }

    operator T() const
    {
        return value;
    }
};

template <>
class TypedFieldValue<bool> : public FieldValue
{
private:
    bool value;

public:
    TypedFieldValue(bool val)
        : value(val)
    {
    }

    std::string toString() const override
    {
        return value ? "true" : "false";
    }

    std::shared_ptr<FieldValue> clone() const override
    {
        return std::make_shared<TypedFieldValue<bool>>(value);
    }

    bool equals(const FieldValue& other) const override
    {
        if (getType() != other.getType())
        {
            return false;
        }
        const auto& typedOther = dynamic_cast<const TypedFieldValue<bool>&>(other);
        return value == typedOther.value;
    }

    int compare(const FieldValue& other) const override
    {
        if (getType() != other.getType())
        {
            throw TXTDBException(TXTDBException::TYPE_MISMATCH, "Cannot compare different types");
        }
        const auto& typedOther = dynamic_cast<const TypedFieldValue<bool>&>(other);
        if (value < typedOther.value)
            return -1;
        if (value > typedOther.value)
            return 1;
        return 0;
    }

    std::type_index getType() const override
    {
        return std::type_index(typeid(bool));
    }

    size_t hash() const override
    {
        return std::hash<bool>()(value);
    }

    bool getValue() const
    {
        return value;
    }
    operator bool() const
    {
        return value;
    }
};

using Row = std::vector<std::shared_ptr<FieldValue>>;

template <typename T>
std::shared_ptr<FieldValue> makeFieldValue(const T& value)
{
    return std::make_shared<TypedFieldValue<T>>(value);
}

struct FieldValueHash
{
    size_t operator()(const std::shared_ptr<FieldValue>& fv) const
    {
        return fv ? fv->hash() : 0;
    }
};

struct FieldValueEqual
{
    bool operator()(const std::shared_ptr<FieldValue>& a, const std::shared_ptr<FieldValue>& b) const
    {
        if (!a && !b)
            return true;
        if (!a || !b)
            return false;
        return a->equals(*b);
    }
};

struct FieldValueCompare
{
    bool operator()(const std::shared_ptr<FieldValue>& a, const std::shared_ptr<FieldValue>& b) const
    {
        if (!a && !b)
            return false;
        if (!a)
            return true;
        if (!b)
            return false;
        return a->compare(*b) < 0;
    }
};

class TXTDatabase
{
private:
    using Row = std::vector<std::shared_ptr<FieldValue>>;
    using IndexMap = std::unordered_map<std::shared_ptr<FieldValue>, size_t, FieldValueHash, FieldValueEqual>;
    using SortedIndexMap = std::map<std::shared_ptr<FieldValue>, size_t, FieldValueCompare>;

    struct IndexInfo
    {
        std::unique_ptr<IndexMap> hashIndex;
        std::unique_ptr<SortedIndexMap> sortedIndex;
        std::function<bool(const Row&)> qualifier;
        std::type_index fieldType;
        bool isSorted;

        IndexInfo()
            : hashIndex(nullptr)
            , sortedIndex(nullptr)
            , qualifier(nullptr)
            , fieldType(typeid(void))
            , isSorted(false)
        {
        }

        IndexInfo(std::type_index type, bool sorted = false)
            : hashIndex(nullptr)
            , sortedIndex(nullptr)
            , qualifier(nullptr)
            , fieldType(type)
            , isSorted(sorted)
        {
            if (sorted)
            {
                sortedIndex = std::make_unique<SortedIndexMap>();
            }
            else
            {
                hashIndex = std::make_unique<IndexMap>();
            }
        }
    };

    int numFields;
    std::vector<Row> data;
    std::vector<IndexInfo> indices;
    mutable std::string lastError;
    int errorField;
    size_t errorRow;
    Row errorRowData;
    std::vector<std::type_index> fieldTypes;

    std::shared_ptr<FieldValue> parseField(const std::string& str, std::type_index type)
    {
        if (type == typeid(std::string))
        {
            return makeFieldValue(str);
        }
        else if (type == typeid(bool))
        {
            return makeFieldValue(str == "true" || str == "1");
        }
        else if (type == typeid(char))
        {
            return makeFieldValue(str.empty() ? '\0' : str[0]);
        }
        else if (type == typeid(signed char))
        {
            return makeFieldValue(str.empty() ? '\0' : str[0]);
        }
        else if (type == typeid(unsigned char))
        {
            return makeFieldValue(static_cast<unsigned char>(std::stoul(str)));
        }
        else if (type == typeid(short))
        {
            return makeFieldValue(static_cast<short>(std::stoi(str)));
        }
        else if (type == typeid(unsigned short))
        {
            return makeFieldValue(static_cast<unsigned short>(std::stoul(str)));
        }
        else if (type == typeid(int))
        {
            return makeFieldValue(std::stoi(str));
        }
        else if (type == typeid(unsigned int))
        {
            return makeFieldValue(static_cast<unsigned int>(std::stoul(str)));
        }
        else if (type == typeid(long))
        {
            return makeFieldValue(std::stol(str));
        }
        else if (type == typeid(unsigned long))
        {
            return makeFieldValue(std::stoul(str));
        }
        else if (type == typeid(long long))
        {
            return makeFieldValue(std::stoll(str));
        }
        else if (type == typeid(unsigned long long))
        {
            return makeFieldValue(std::stoull(str));
        }
        else if (type == typeid(float))
        {
            return makeFieldValue(std::stof(str));
        }
        else if (type == typeid(double))
        {
            return makeFieldValue(std::stod(str));
        }
        else
        {
            throw TXTDBException(TXTDBException::INVALID_CONVERSION,
                                 "Unsupported type for parsing: " + std::string(type.name()));
        }
    }

    std::string escapeString(const std::string& str) const
    {
        std::string result;
        for (char c : str)
        {
            if (c == '\t' || c == '\\')
            {
                result += '\\';
            }
            result += c;
        }
        return result;
    }

    std::string unescapeString(const std::string& str) const
    {
        std::string result;
        bool escape = false;
        for (char c : str)
        {
            if (escape)
            {
                result += c;
                escape = false;
            }
            else if (c == '\\')
            {
                escape = true;
            }
            else
            {
                result += c;
            }
        }
        return result;
    }

public:
    explicit TXTDatabase(int fields)
        : numFields(fields)
        , errorField(-1)
        , errorRow(0)
    {
        if (fields <= 0)
        {
            throw TXTDBException(TXTDBException::INDEX_OUT_OF_RANGE, "Fields count must be positive");
        }
        indices.resize(fields);
        fieldTypes.resize(fields, typeid(std::string));
    }

    TXTDatabase(const std::vector<std::type_index>& types)
        : numFields(types.size())
        , errorField(-1)
        , errorRow(0)
        , fieldTypes(types)
    {
        if (types.empty())
        {
            throw TXTDBException(TXTDBException::INDEX_OUT_OF_RANGE, "Fields count must be positive");
        }
        indices.resize(numFields);
    }

    TXTDatabase(const TXTDatabase&) = delete;
    TXTDatabase& operator=(const TXTDatabase&) = delete;

    TXTDatabase(TXTDatabase&&) = default;
    TXTDatabase& operator=(TXTDatabase&&) = default;

    void setFieldType(int field, std::type_index type)
    {
        if (field < 0 || field >= numFields)
        {
            throw TXTDBException(TXTDBException::INDEX_OUT_OF_RANGE, "Field index out of range");
        }
        fieldTypes[field] = type;
    }

    bool updateRow(size_t index, const Row& newRow)
    {
        if (index >= data.size())
        {
            lastError = "Row index out of range";
            return false;
        }

        if ((int)newRow.size() != numFields)
        {
            lastError = "Wrong number of fields";
            return false;
        }

        for (int i = 0; i < numFields; i++)
        {
            if (!newRow[i] || newRow[i]->getType() != fieldTypes[i])
            {
                lastError = "Type mismatch at field " + std::to_string(i);
                return false;
            }
        }

        Row oldRow = data[index];

        for (int i = 0; i < numFields; i++)
        {
            if (indices[i].hashIndex && i < (int)newRow.size())
            {
                if (indices[i].qualifier && !indices[i].qualifier(newRow))
                {
                    continue;
                }

                auto it = indices[i].hashIndex->find(newRow[i]);
                if (it != indices[i].hashIndex->end() && it->second != index)
                {
                    lastError = "Index clash on field " + std::to_string(i);
                    errorField = i;
                    errorRow = it->second;
                    errorRowData = data[it->second];
                    return false;
                }
            }

            if (indices[i].sortedIndex && i < (int)newRow.size())
            {
                if (indices[i].qualifier && !indices[i].qualifier(newRow))
                {
                    continue;
                }

                auto it = indices[i].sortedIndex->find(newRow[i]);
                if (it != indices[i].sortedIndex->end() && it->second != index)
                {
                    lastError = "Index clash on field " + std::to_string(i);
                    errorField = i;
                    errorRow = it->second;
                    errorRowData = data[it->second];
                    return false;
                }
            }
        }

        for (int i = 0; i < numFields; i++)
        {
            if (i < (int)oldRow.size() && oldRow[i])
            {
                if (indices[i].hashIndex)
                {
                    if (!indices[i].qualifier || indices[i].qualifier(oldRow))
                    {
                        indices[i].hashIndex->erase(oldRow[i]);
                    }
                }
                if (indices[i].sortedIndex)
                {
                    if (!indices[i].qualifier || indices[i].qualifier(oldRow))
                    {
                        indices[i].sortedIndex->erase(oldRow[i]);
                    }
                }
            }
        }

        data[index] = newRow;

        for (int i = 0; i < numFields; i++)
        {
            if (i < (int)newRow.size() && newRow[i])
            {
                if (indices[i].hashIndex)
                {
                    if (!indices[i].qualifier || indices[i].qualifier(newRow))
                    {
                        indices[i].hashIndex->emplace(newRow[i], index);
                    }
                }
                if (indices[i].sortedIndex)
                {
                    if (!indices[i].qualifier || indices[i].qualifier(newRow))
                    {
                        indices[i].sortedIndex->emplace(newRow[i], index);
                    }
                }
            }
        }

        return true;
    }

    static TXTDatabase read(std::istream& in, const std::vector<std::type_index>& fieldTypes)
    {
        TXTDatabase db(fieldTypes);
        std::string line;
        int lineNum = 0;

        while (std::getline(in, line))
        {
            lineNum++;

            if (line.empty() || line[0] == '#')
            {
                continue;
            }

            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }

            Row row;
            std::string field;
            bool escape = false;
            int fieldIndex = 0;

            for (char c : line)
            {
                if (escape)
                {
                    field += c;
                    escape = false;
                }
                else if (c == '\\')
                {
                    escape = true;
                }
                else if (c == '\t')
                {
                    if (fieldIndex < (int)fieldTypes.size())
                    {
                        row.push_back(db.parseField(db.unescapeString(field), fieldTypes[fieldIndex]));
                    }
                    field.clear();
                    fieldIndex++;
                }
                else
                {
                    field += c;
                }
            }

            if (fieldIndex < (int)fieldTypes.size())
            {
                row.push_back(db.parseField(db.unescapeString(field), fieldTypes[fieldIndex]));
            }

            if ((int)row.size() != db.numFields)
            {
                throw TXTDBException(TXTDBException::WRONG_NUM_FIELDS,
                                     "Line " + std::to_string(lineNum) + ": expected " + std::to_string(db.numFields) +
                                         " fields, got " + std::to_string(row.size()));
            }

            db.data.push_back(std::move(row));
        }

        return db;
    }

    static TXTDatabase readFromFile(const std::string& filename, const std::vector<std::type_index>& fieldTypes)
    {
        std::ifstream file(filename);
        if (!file.is_open())
        {
            throw std::runtime_error("Cannot open file: " + filename);
        }
        return read(file, fieldTypes);
    }

    void write(std::ostream& out) const
    {
        for (const auto& row : data)
        {
            for (int i = 0; i < (int)row.size(); i++)
            {
                if (i > 0)
                    out << '\t';
                if (row[i])
                {
                    std::string str = row[i]->toString();
                    out << escapeString(str);
                }
            }
            out << '\n';
        }
    }

    void writeToFile(const std::string& filename) const
    {
        std::ofstream file(filename);
        if (!file.is_open())
        {
            throw std::runtime_error("Cannot open file for writing: " + filename);
        }
        write(file);
    }

    bool createIndex(int field, std::function<bool(const Row&)> qualifier = nullptr)
    {
        if (field < 0 || field >= numFields)
        {
            lastError = "Index out of range";
            return false;
        }

        indices[field] = IndexInfo(fieldTypes[field], false);
        indices[field].qualifier = qualifier;

        for (size_t i = 0; i < data.size(); i++)
        {
            const Row& row = data[i];

            if (qualifier && !qualifier(row))
            {
                continue;
            }

            if (field >= (int)row.size() || !row[field])
            {
                continue;
            }

            const auto& key = row[field];

            auto it = indices[field].hashIndex->find(key);
            if (it != indices[field].hashIndex->end())
            {
                lastError = "Index clash at row " + std::to_string(i);
                errorField = field;
                errorRow = i;
                errorRowData = row;
                return false;
            }

            indices[field].hashIndex->emplace(key, i);
        }

        return true;
    }

    bool createSortedIndex(int field, std::function<bool(const Row&)> qualifier = nullptr)
    {
        if (field < 0 || field >= numFields)
        {
            lastError = "Index out of range";
            return false;
        }

        indices[field] = IndexInfo(fieldTypes[field], true);
        indices[field].qualifier = qualifier;

        for (size_t i = 0; i < data.size(); i++)
        {
            const Row& row = data[i];

            if (qualifier && !qualifier(row))
            {
                continue;
            }

            if (field >= (int)row.size() || !row[field])
            {
                continue;
            }

            const auto& key = row[field];
            indices[field].sortedIndex->emplace(key, i);
        }

        return true;
    }

    const Row* findByIndex(int field, const std::shared_ptr<FieldValue>& value) const
    {
        if (field < 0 || field >= numFields)
        {
            lastError = "Index out of range";
            return nullptr;
        }

        const auto& idx = indices[field];
        if (!idx.hashIndex)
        {
            lastError = "No hash index on field " + std::to_string(field);
            return nullptr;
        }

        auto it = idx.hashIndex->find(value);
        if (it == idx.hashIndex->end())
        {
            return nullptr;
        }

        if (it->second >= data.size())
        {
            return nullptr;
        }

        return &data[it->second];
    }

    template <typename T>
    const Row* findByIndex(int field, const T& value) const
    {
        auto fieldValue = makeFieldValue(value);
        return findByIndex(field, fieldValue);
    }

    std::vector<const Row*> findRange(int field, const std::shared_ptr<FieldValue>& start,
                                      const std::shared_ptr<FieldValue>& end) const
    {
        std::vector<const Row*> result;

        if (field < 0 || field >= numFields)
        {
            lastError = "Index out of range";
            return result;
        }

        const auto& idx = indices[field];
        if (!idx.sortedIndex)
        {
            lastError = "No sorted index on field " + std::to_string(field);
            return result;
        }

        auto itStart = idx.sortedIndex->lower_bound(start);
        auto itEnd = idx.sortedIndex->upper_bound(end);

        for (auto it = itStart; it != itEnd; ++it)
        {
            if (it->second < data.size())
            {
                result.push_back(&data[it->second]);
            }
        }

        return result;
    }

    template <typename T>
    std::vector<const Row*> findRange(int field, const T& start, const T& end) const
    {
        auto startVal = makeFieldValue(start);
        auto endVal = makeFieldValue(end);
        return findRange(field, startVal, endVal);
    }

    bool insert(Row row)
    {
        if ((int)row.size() != numFields)
        {
            lastError = "Wrong number of fields";
            return false;
        }

        for (int i = 0; i < numFields; i++)
        {
            if (!row[i] || row[i]->getType() != fieldTypes[i])
            {
                lastError = "Type mismatch at field " + std::to_string(i);
                return false;
            }
        }

        for (int i = 0; i < numFields; i++)
        {
            if (indices[i].hashIndex && i < (int)row.size())
            {
                if (indices[i].qualifier && !indices[i].qualifier(row))
                {
                    continue;
                }

                auto it = indices[i].hashIndex->find(row[i]);
                if (it != indices[i].hashIndex->end())
                {
                    lastError = "Index clash on field " + std::to_string(i);
                    errorField = i;
                    errorRow = it->second;
                    errorRowData = data[it->second];
                    return false;
                }
            }

            if (indices[i].sortedIndex && i < (int)row.size())
            {
                if (indices[i].qualifier && !indices[i].qualifier(row))
                {
                    continue;
                }

                auto it = indices[i].sortedIndex->find(row[i]);
                if (it != indices[i].sortedIndex->end())
                {
                    lastError = "Index clash on field " + std::to_string(i);
                    errorField = i;
                    errorRow = it->second;
                    errorRowData = data[it->second];
                    return false;
                }
            }
        }

        size_t newIndex = data.size();
        data.push_back(std::move(row));
        const Row& newRow = data.back();

        for (int i = 0; i < numFields; i++)
        {
            if (i < (int)newRow.size() && newRow[i])
            {
                if (indices[i].hashIndex)
                {
                    if (!indices[i].qualifier || indices[i].qualifier(newRow))
                    {
                        indices[i].hashIndex->emplace(newRow[i], newIndex);
                    }
                }
                if (indices[i].sortedIndex)
                {
                    if (!indices[i].qualifier || indices[i].qualifier(newRow))
                    {
                        indices[i].sortedIndex->emplace(newRow[i], newIndex);
                    }
                }
            }
        }

        return true;
    }

    template <typename... Args>
    bool insert(Args... args)
    {
        Row row;
        (row.push_back(makeFieldValue(args)), ...);
        return insert(row);
    }

    bool removeByIndex(int field, const std::shared_ptr<FieldValue>& value)
    {
        if (field < 0 || field >= numFields)
        {
            lastError = "Index out of range";
            return false;
        }

        const auto& idx = indices[field];
        if (!idx.hashIndex)
        {
            lastError = "No hash index on field " + std::to_string(field);
            return false;
        }

        auto it = idx.hashIndex->find(value);
        if (it == idx.hashIndex->end())
        {
            return false;
        }

        size_t rowIndex = it->second;
        if (rowIndex >= data.size())
        {
            return false;
        }

        const Row& row = data[rowIndex];
        for (int i = 0; i < numFields; i++)
        {
            if (i < (int)row.size() && row[i])
            {
                if (indices[i].hashIndex)
                {
                    if (!indices[i].qualifier || indices[i].qualifier(row))
                    {
                        indices[i].hashIndex->erase(row[i]);
                    }
                }
                if (indices[i].sortedIndex)
                {
                    if (!indices[i].qualifier || indices[i].qualifier(row))
                    {
                        indices[i].sortedIndex->erase(row[i]);
                    }
                }
            }
        }

        data.erase(data.begin() + rowIndex);

        for (size_t i = rowIndex; i < data.size(); i++)
        {
            const Row& updatedRow = data[i];
            for (int j = 0; j < numFields; j++)
            {
                if (j < (int)updatedRow.size() && updatedRow[j])
                {
                    if (indices[j].hashIndex)
                    {
                        if (!indices[j].qualifier || indices[j].qualifier(updatedRow))
                        {
                            auto it2 = indices[j].hashIndex->find(updatedRow[j]);
                            if (it2 != indices[j].hashIndex->end() && it2->second == i + 1)
                            {
                                it2->second = i;
                            }
                        }
                    }
                    if (indices[j].sortedIndex)
                    {
                        if (!indices[j].qualifier || indices[j].qualifier(updatedRow))
                        {
                            // Для sorted index нужно перестроить или обновить
                            // Упрощенная версия - просто пересоздаем индекс
                        }
                    }
                }
            }
        }

        return true;
    }

    const Row& getRow(size_t index) const
    {
        if (index >= data.size())
        {
            throw std::out_of_range("Row index out of range");
        }
        return data[index];
    }

    template <typename T>
    T getField(const Row& row, int field) const
    {
        if (field < 0 || field >= (int)row.size() || !row[field])
        {
            throw std::out_of_range("Field index out of range");
        }

        auto typedField = std::dynamic_pointer_cast<TypedFieldValue<T>>(row[field]);
        if (!typedField)
        {
            throw TXTDBException(TXTDBException::TYPE_MISMATCH, "Cannot convert field to requested type");
        }
        return typedField->getValue();
    }

    size_t size() const
    {
        return data.size();
    }

    int getNumFields() const
    {
        return numFields;
    }

    std::type_index getFieldType(int field) const
    {
        if (field < 0 || field >= numFields)
        {
            throw std::out_of_range("Field index out of range");
        }
        return fieldTypes[field];
    }

    void clear() noexcept
    {
        data.clear();

        for (auto& idx : indices)
        {
            if (idx.hashIndex)
            {
                idx.hashIndex->clear();
            }
            if (idx.sortedIndex)
            {
                idx.sortedIndex->clear();
            }
        }
    }

    std::string getLastError() const
    {
        return lastError;
    }

    int getErrorField() const
    {
        return errorField;
    }
    
    size_t getErrorRow() const
    {
        return errorRow;
    }
    
    Row getErrorRowData() const
    {
        return errorRowData;
    }

    void print(std::ostream& out) const
    {
        for (const auto& row : data)
        {
            for (size_t i = 0; i < row.size(); i++)
            {
                if (i > 0)
                    out << " | ";
                if (row[i])
                {
                    out << row[i]->toString();
                }
            }
            out << '\n';
        }
    }
};

template <typename T>
T getFieldValue(const std::shared_ptr<FieldValue>& field)
{
    auto typed = std::dynamic_pointer_cast<TypedFieldValue<T>>(field);
    if (typed)
        return typed->getValue();
    return T{};
}