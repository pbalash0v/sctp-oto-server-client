#pragma once

#include <arpa/inet.h>
#include <usrsctp.h>

#include "iclient.h"

struct SCTPMessage
{
	enum Type
	{
		MESSAGE,
		NOTIFICATION
	};

	SCTPMessage() = default;
	explicit SCTPMessage(Type, std::shared_ptr<IClient>, void*, size_t, 
					struct sockaddr_in&, struct sctp_recvv_rn, unsigned int);
	explicit SCTPMessage(Type, std::shared_ptr<IClient>, void*, size_t);

	SCTPMessage(const SCTPMessage& oth) = delete;
	SCTPMessage& operator=(const SCTPMessage& oth) = delete;

	virtual ~SCTPMessage();
	
	Type type;
	std::shared_ptr<IClient> client;
	void* msg { nullptr };
	size_t size { 0 };
	struct sockaddr_in addr;	
	struct sctp_recvv_rn rn;
	unsigned int infotype;
};



