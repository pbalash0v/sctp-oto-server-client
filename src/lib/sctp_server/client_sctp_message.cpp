#include <memory>
#include <cstring>

#include "client_sctp_message.hpp"

namespace sctp
{

Message::Message(Type tp, std::shared_ptr<Server::IClient> c, void* b, size_t s,
					struct sockaddr_in& a, struct sctp_recvv_rn r, unsigned int t)
	: type(tp), client(c), size(s), addr(a), rn(r), infotype(t)
{
	msg = calloc(s, sizeof(char));
	if (not msg) throw std::runtime_error("Calloc failed.");

	memcpy(msg, b, s);
	size = s;
};

Message::Message(Type t, std::shared_ptr<Server::IClient> c, void* b, size_t s)
	: type(t), client(c), size(s)
{
	msg = calloc(s, sizeof(char));
	if (not msg) throw std::runtime_error("Calloc failed.");

	memcpy(msg, b, s);
	size = s;
}

Message::~Message()
{
	std::free(msg);
}

} // namespace sctp
