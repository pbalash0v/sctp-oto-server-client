#include <sstream>

#include "sctp_server.hpp"
#include "sctp_server_impl.hpp"


namespace sctp
{

Server::Server(std::shared_ptr<Server::Config> cfg)
	: server_impl_ptr_{std::make_unique<ServerImpl>(cfg)}
{
}

Server::~Server()
{
}

std::shared_ptr<Server::Config> Server::cfg()
{
	return server_impl_ptr_->cfg();
}

void Server::operator()()
{
	server_impl_ptr_->operator()();
}

void Server::send(std::shared_ptr<Server::IClient> cli, const void* buf, size_t len)
{
	server_impl_ptr_->send(cli, buf, len);
}

void Server::stop()
{
	server_impl_ptr_->stop();
}


std::ostream& operator<<(std::ostream& out, const Server::Config& c)
{
	std::ostringstream ss;
	ss << "UDP encaps port: " << std::to_string(c.udp_encaps_port) << ", "
		<< "SCTP port: " << std::to_string(c.sctp_port) << ", "
		<< "Event callback: " << (c.event_cback_f == nullptr ? "not set" : "set") << ", "
		<< "Debug callback: " << (c.debug_cback_f == nullptr ? "not set" : "set") << ", "
		<< "SSL certificate: " << c.cert_filename << ", "
		<< "SSL key: " << c.key_filename;

	return out << ss.str();
}

std::ostream& operator<<(std::ostream &out, const Server& s)
{
	out << *(s.server_impl_ptr_->cfg());
	return out;
}

} // namespace sctp

