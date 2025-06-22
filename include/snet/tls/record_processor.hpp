#pragma once
#include <vector>
#include <memory>
#include <snet/tls/i_record_handler.hpp>

namespace snet::tls
{

using RecordHandlers = std::vector<std::shared_ptr<IRecordHandler>>;

using RecordProcessor = std::shared_ptr<RecordHandlers>;

} // namespace snet::tls