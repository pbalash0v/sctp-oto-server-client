#pragma once

#include <iostream>
#include <vector>
#include <memory>


class SCTPServer;
struct SCTPMessage;
struct Event;

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
		SCTP_SHUTDOWN_CMPLT,
		SCTP_SRV_INITIATED_SHUTDOWN,
		PURGE
   };


	virtual ~IClient() {};

	virtual void init() = 0;

	virtual void state(IClient::State) = 0;
	virtual IClient::State state() const = 0;

	virtual struct socket* socket() const = 0;

	virtual size_t send(const void* buf, size_t len) = 0;
	virtual ssize_t send_raw(const void* buf, size_t len) = 0;

	virtual std::unique_ptr<Event> handle_message(const std::unique_ptr<SCTPMessage>&) = 0;

	virtual void close() = 0;

	virtual std::vector<char>& sctp_msg_buff() = 0;

	virtual std::string to_string() const = 0;

	friend std::ostream& operator<<(std::ostream &out, const IClient::State s);
};


