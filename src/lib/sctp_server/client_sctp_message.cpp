#include <memory>
#include <cstring>

#include "client_sctp_message.h"


SCTPMessage::SCTPMessage(const void* buf, size_t len)
{
	data = calloc(len, sizeof(char));
	if (not data) throw std::runtime_error("Calloc failed.");

	memcpy(data, buf, len);
	size = len;
}

SCTPMessage::~SCTPMessage() {
	std::free(data);
}

