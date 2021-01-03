#pragma once

#include <memory>

#include "iclient.h"
#include "client.h"


namespace sctp
{
struct Message;
}

struct Event
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

	Event::Type type {IClient::State::NONE};
	std::shared_ptr<IClient> client {nullptr};
	IClient::State client_state {IClient::State::NONE};
	std::vector<char> client_data;
};
