#include <memory>
#include <cstring>

#include "client_sctp_message.h"

SCTPMessage::SCTPMessage(std::shared_ptr<IClient> c, void* b, size_t s, 
					struct sockaddr_in& a, struct sctp_recvv_rn r, unsigned int t)
	: client(c), msg(b), size(s), addr(a), rn(r), infotype(t)
{
	msg = calloc(s, sizeof(char));
	if (not msg) throw std::runtime_error("Calloc failed.");

	memcpy(msg, b, s);
	size = s;
};


SCTPMessage::~SCTPMessage()
{
	std::free(msg);
}

