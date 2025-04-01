#pragma once
#include <libmnl/libmnl.h>

int mnl_cb_run_my(const void* buf, size_t numbytes, unsigned int seq, unsigned int portid,
                  mnl_cb_t cb_data, void* data);