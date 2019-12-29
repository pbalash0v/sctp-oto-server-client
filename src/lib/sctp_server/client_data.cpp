#include <memory>
#include <cstring>

#include "client_data.h"


Data::Data(const void* buf, size_t len)
{
	data = calloc(len, sizeof(char));
	if (not data) throw std::runtime_error("Calloc failed.");

	memcpy(data, buf, len);
	size = len;
}

Data::~Data() {
	std::free(data);
}

