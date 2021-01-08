#include "sctp_server_impl.hpp"
#include "client_sctp_message.hpp"

namespace sctp
{

ServerEvent::ServerEvent(ServerEvent::Type t, std::shared_ptr<Server::IClient> clnt)
	: type(t), client(clnt) {};

ServerEvent::ServerEvent(ServerEvent::Type t, std::shared_ptr<Server::IClient> clnt, Server::IClient::State s)
	: type(t), client(clnt), client_state(s) {};

ServerEvent::ServerEvent(ServerEvent::Type t, std::shared_ptr<Server::IClient> clnt, std::vector<char> v)
	: type(t), client(clnt), client_data(std::move(v)) {};

ServerEvent::ServerEvent(const sctp::Message& m) : client(m.client) {};

} // namespace sctp