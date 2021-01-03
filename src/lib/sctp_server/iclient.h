#pragma once

#include <vector>
#include <memory>


class SCTPServer;
namespace sctp
{
struct Message;
}
struct Event;

class IClient
{
public:
   enum class State
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

	virtual void send(const void* buf, size_t len) = 0;

	virtual std::unique_ptr<Event> handle_message(const std::unique_ptr<sctp::Message>&) = 0;

	virtual void close() = 0;

	virtual std::vector<char>& sctp_msg_buff() = 0;

	virtual std::string to_string() const = 0;

	friend std::ostream& operator<<(std::ostream& out, const IClient& c)
	{
		return out << c.to_string();
	};

	friend std::ostream& operator<<(std::ostream &out, const IClient::State s);
};


