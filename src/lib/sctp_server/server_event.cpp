#include "server_event.h"

Event::Event(Event::Type t, std::shared_ptr<IClient> clnt)
	: type(t), client(clnt) {};

Event::Event(Event::Type t, std::shared_ptr<IClient> clnt, IClient::State s)
	: type(t), client(clnt), client_state(s) {};

Event::Event(Event::Type t, std::shared_ptr<IClient> clnt, std::unique_ptr<Data> d)
	: type(t), client(clnt), client_data(std::move(d)) {};