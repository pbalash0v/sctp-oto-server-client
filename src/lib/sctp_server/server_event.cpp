#include "server_event.h"
#include "client_sctp_message.h"

Event::Event(Event::Type t, std::shared_ptr<IClient> clnt)
	: type(t), client(clnt) {};

Event::Event(Event::Type t, std::shared_ptr<IClient> clnt, IClient::State s)
	: type(t), client(clnt), client_state(s) {};

Event::Event(Event::Type t, std::shared_ptr<IClient> clnt, std::vector<char> v)
	: type(t), client(clnt), client_data(std::move(v)) {};

Event::Event(const sctp::Message& m) : client(m.client) {};
