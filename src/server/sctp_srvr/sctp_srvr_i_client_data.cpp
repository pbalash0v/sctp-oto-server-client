#include <memory>
#include <cstring>

#include <sctp_srvr_i_client.h>



IClient::Data::Data(const void* buf, size_t len)
{
	data = calloc(len, sizeof(char));
	if (not data) throw std::runtime_error("Calloc failed.");

	memcpy(data, buf, len);
	size = len;
}

IClient::Data::~Data() {
	std::free(data);
}


