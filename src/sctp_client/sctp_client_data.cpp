#include <memory>
#include <cstring>

#include "sctp_client.h"


SCTPClient::Data::Data(const void* buf, size_t len)
{
	data = calloc(len, sizeof(char));
	if (not data) throw std::runtime_error("Calloc failed.");

	memcpy(data, buf, len);
	size = len;
}

SCTPClient::Data::~Data() {
	std::free(data);
}

