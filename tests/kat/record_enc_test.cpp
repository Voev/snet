#include <common/types/vector.h>
#include <common/types/string.h>

#include <tests/filter/gtest_compat.h>
#include <tests/filter/name_generator.h>

#include <auxiliary/iptable_local.h>
#include <auxiliary/ini_parser.h>

#include <filter/xt_registry.h>

using namespace testing;

namespace df
{

static String TEST_NAME = "nat_translator";
static String TABLE_PATH = "table_path";
static String PCAP_IN_PATH = "pcap_in_path";
static String PCAP_OUT_PATH = "pcap_out_path";

struct RecordEncryptionTestParam
{
    std:: testName;
    String pcapInputPath;
    String pcapOutputPath;
    String tablePath;
};

static Vector<RecordEncryptionTestParam> create_params()
{
    Vector<RecordEncryptionTestParam> params;
    auto sections = IniFileParser::get_instance().get_sections();

    for (const auto& section : sections)
    {
        if (section.first.find(TEST_NAME) != String::npos)
        {
            RecordEncryptionTestParam param;
            param.testName = section.first;

            for (const auto& option : section.second)
            {
                if (equals(option.first, TABLE_PATH))
                {
                    param.tablePath = option.second;
                }
                else if (equals(option.first, PCAP_IN_PATH))
                {
                    param.pcapInputPath = option.second;
                }
                else if (equals(option.first, PCAP_OUT_PATH))
                {
                    param.pcapInputPath = option.second;
                }
                else
                {
                    throw std::runtime_error("Unknown options for section '" + section.first + "': (" + option.first +
                                             ", " + option.second + ")");
                }
            }

            params.emplace_back(std::move(param));
        }
    }

    return params;
}

class RecordEncryptionTest : public TestWithParam<RecordEncryptionTestParam>
{
public:
    void SetUp() override
    {
        const auto& param = GetParam();

        register_targets();
        register_matches();

        auto meminitret = memory_.init(QuotaMemPolicy::Strict);
        ASSERT_TRUE(meminitret.has_value()) << meminitret.error().message();

        MemorySize<MegaBytes> quota{10};
        ASSERT_TRUE(memory_.set_quota(MemorySize<Bytes>(quota)));

        auto table = IPTableLocal::load_table_from_file(param.tablePath, &memory_);
        ASSERT_TRUE(table.has_value()) << table.error().message();

        auto parseret = IPTableLocal::parse_table(table.value());
        EXPECT_TRUE(parseret.has_value()) << parseret.error().message();
    }

    void TearDown() override
    {
        IPTableLocal::unload_table(table_.value_or(nullptr), &memory_);

        unregister_targets();
        unregister_matches();
    }

protected:
    MemoryDistributor memory_;
    Expected<IPTableLocal*> table_;
};

TEST_P(RecordEncryptionTest, EncryptRecord)
{
}

INSTANTIATE_TEST_CASE_P(NAT, RecordEncryptionTest, ValuesIn(create_params()), NameGenerator<RecordEncryptionTestParam>);

} // namespace df
