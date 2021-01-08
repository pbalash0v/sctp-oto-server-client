#ifndef __sctp_event_hpp__
#define __sctp_event_hpp__

#include <memory>

#include "iclient.hpp"


namespace sctp
{
struct Message;

struct ServerEvent
{
	enum class Type
	{
		NONE,
		CLIENT_DATA,
		CLIENT_STATE,
		CLIENT_SEND_POSSIBLE,
		ERROR
	};

	explicit Event(Event::Type, std::shared_ptr<IClient>);	
	explicit Event(Event::Type, std::shared_ptr<IClient>, IClient::State);
	explicit Event(Event::Type, std::shared_ptr<IClient>, std::vector<char>);
	explicit Event(const sctp::Message&);

	Event(const Event&) = delete;
	Event& operator=(const Event&) = delete;
	virtual ~Event() = default;

	Event::Type type {Event::Type::NONE};
	std::shared_ptr<IClient> client {nullptr};
	IClient::State client_state {IClient::State::NONE};
	std::vector<char> client_data;
};

}

#endif // __sctp_event_hpp__