#include <sstream>

#include "sctp_client.hpp"
#include "sctp_client_impl.hpp"


namespace sctp
{

Client::Client(std::shared_ptr<Client::Config> cfg)
	: client_impl_ptr_{std::make_unique<ClientImpl>(cfg)}
{
}

Client::~Client() = default;

std::shared_ptr<Client::Config> Client::cfg()
{
	return client_impl_ptr_->cfg_;
}

const std::shared_ptr<Client::Config> Client::cfg() const
{
	return client_impl_ptr_->cfg_;
}

void Client::operator()()
{
	client_impl_ptr_->operator()();
}

bool Client::connected() const noexcept
{
	return client_impl_ptr_->state_ == Client::State::SSL_CONNECTED;
}

ssize_t Client::send(const void* data, size_t len)
{
	return client_impl_ptr_->send(data, len);
}

void Client::stop()
{
	client_impl_ptr_->stop();
}

std::string Client::to_string() const
{
	std::ostringstream oss;
	oss << *this;
	return oss.str();
}

std::ostream& operator<<(std::ostream& out, const Client::Config& c)
{
	std::ostringstream ss;

	ss << "local UDP encaps port: " << std::to_string(c.udp_encaps_port) << ", "
		<< "server UDP encaps port: " << std::to_string(c.server_udp_port) << ", "
		<< "server address: " << c.server_address << ", "
		<< "server SCTP port: " << std::to_string(c.server_sctp_port) << ", "
		<< "data callback: " << (c.data_cback_f == nullptr ? "nullptr" : "set") << ", "
		<< "debug callback: " << (c.debug_cback_f == nullptr ? "nullptr" : "set") << ", "
		<< "state callback: " << (c.state_cback_f == nullptr ? "nullptr" : "set") << ", "
		<< "SSL certificate: " << c.cert_filename << ", "
		<< "SSL key: " << c.key_filename;
	
	return out << ss.str();
}

std::ostream& operator<<(std::ostream& out, const Client& cli)
{
	return out << ":" << htons(cli.client_impl_ptr_->bound_udp_encaps_port_)
		<< " -> "
		<< (cli.cfg()->server_address) << ":" << cli.cfg()->server_udp_port;
}

} //namespace sctp
