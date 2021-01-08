#pragma once

#include <arpa/inet.h>
#include <usrsctp.h>

//#include "iclient.hpp"
#include "sctp_server.hpp"


namespace sctp
{

struct Message
{
	enum class Type
	{
		DATA,
		NOTIFICATION
	};

	explicit Message(Type, std::shared_ptr<Server::IClient>, void*, size_t,
					struct sockaddr_in&, struct sctp_recvv_rn, unsigned int);
	explicit Message(Type, std::shared_ptr<Server::IClient>, void*, size_t);

	Message(const Message& oth) = delete;
	Message& operator=(const Message& oth) = delete;
	Message(Message&& oth) = default;
	Message& operator=(Message&& oth) = default;

	~Message();

	Type type{};
	std::shared_ptr<Server::IClient> client{};
	void* msg {nullptr};
	size_t size {};
	struct sockaddr_in addr{};
	struct sctp_recvv_rn rn{};
	unsigned int infotype{};
};

}
