#pragma once

#include <iostream>
#include <vector>
#include <memory>

#include "ssl_h.h"

class SCTPServer;


class IClient
{
public:
   enum State
   {
   	NONE,
      SCTP_ACCEPTED,
      SCTP_CONNECTED,
      SSL_HANDSHAKING,
      SSL_CONNECTED,
		SSL_SHUTDOWN,
		SCTP_SRV_INITIATED_SHUTDOWN,
		PURGE
   };


	virtual ~IClient() {};

	virtual void init() = 0;

	virtual void state(IClient::State) = 0;
	virtual IClient::State state() const = 0;

	virtual SCTPServer& server() = 0;
	virtual struct socket* socket() const = 0;

	virtual size_t send(const void* buf, size_t len) = 0;

	virtual void close() = 0;

	virtual std::vector<char>& sctp_msg_buff() = 0;
	virtual std::vector<char>& decrypted_msg_buff() = 0;
	virtual std::vector<char>& encrypted_msg_buff() = 0;

	virtual std::string to_string() const = 0;

	friend std::ostream& operator<<(std::ostream &out, const IClient::State s);
	friend class SCTPServer;

protected:
	SSL* ssl = nullptr;
	BIO* output_bio = nullptr;
	BIO* input_bio = nullptr;
};


