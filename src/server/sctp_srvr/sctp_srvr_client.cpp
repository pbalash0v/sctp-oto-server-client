#include <cassert>
#include <cstring>
#include <sstream>

#include <errno.h>

#include "sctp_srvr_client.h"
#include "sctp_srvr.h"



Client::Client(struct socket* sctp_sock, SCTPServer& s) 
	: IClient(sctp_sock, s) {};


void Client::init()
{
	ssl = SSL_new(server_.ssl_obj_.ctx_);
	assert(ssl);

	output_bio = BIO_new(BIO_s_mem());
	assert(output_bio);

	input_bio = BIO_new(BIO_s_mem());
	assert(input_bio);
	  

	SSL_set_bio(ssl, input_bio, output_bio);

	SSL_set_accept_state(ssl);

	void* buf = calloc(BUFFERSIZE, sizeof(char));
	if (not buf) throw std::runtime_error("Calloc failed.");

	buff = std::move(std::unique_ptr<void, decltype(&std::free)> (buf, std::free));
}


void Client::set_state(Client::State new_state)
{
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	std::shared_ptr<SCTPServer::Config> cfg_ = server_.cfg_;

	/* from here on we can use log macros */
	TRACE_func_entry();

	if (new_state == PURGE and state == PURGE) {
		WARNING("PURGE to PURGE transition.");
		return;
	}

	assert(new_state != state);

	state = new_state;
	
	switch (new_state) {
		case SCTP_ACCEPTED:
		{
			uint16_t event_types[] = {	SCTP_ASSOC_CHANGE,
	                          			SCTP_PEER_ADDR_CHANGE,
	                          			SCTP_REMOTE_ERROR,
	                          			SCTP_SHUTDOWN_EVENT,
	                          			SCTP_ADAPTATION_INDICATION,
	                          			SCTP_PARTIAL_DELIVERY_EVENT
	                          		};
			struct sctp_event event;
			memset(&event, 0, sizeof(event));
			event.se_assoc_id = SCTP_ALL_ASSOC;
			event.se_on = 1;
			for (auto ev_type : event_types) {
				event.se_type = ev_type;
				if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
					ERROR("usrsctp_setsockopt SCTP_EVENT for " + to_string());
					throw std::runtime_error(std::string("setsockopt SCTP_EVENT: ") + strerror(errno));
				}
			}

			if (usrsctp_set_upcall(sock, &SCTPServer::handle_client_upcall, &server_)) {
				ERROR("usrsctp_set_upcall for " + to_string());
				throw std::runtime_error(strerror(errno));
			}
		}
			break;
		case SCTP_CONNECTED:
			break;
		case SCTP_SRV_INITIATED_SHUTDOWN:
			usrsctp_shutdown(sock, SHUT_WR);
			break;
		case PURGE:
			struct linger linger_option;
			linger_option.l_onoff = 1;
			linger_option.l_linger = 0;
			if (usrsctp_setsockopt(sock, SOL_SOCKET,
					 SO_LINGER, &linger_option, sizeof(linger_option))) {
				ERROR("Could not set linger options for: "
						 + to_string() 
						 + std::string(strerror(errno)));
			}
			usrsctp_close(sock);
			break;
		default:
			break;
	}

	TRACE_func_left();
}


Client::~Client()
{
	if (nullptr != ssl) SSL_free(ssl);
};


std::string Client::to_string() const
{
	std::ostringstream oss;
	oss << *this;
	return oss.str();
}


std::ostream& operator<<(std::ostream &out, const Client& c)
{
	out << std::string("Client: socket: ") << ((const void*) c.sock) << ", ";
	out << c.state;
	return out;
}


std::ostream& operator<<(std::ostream &out, const Client::State s)
{
	std::string state_name;

	switch (s) {
		case Client::NONE:
			state_name = "NONE";
			break;
		case Client::SCTP_ACCEPTED:
			state_name = "SCTP_ACCEPTED";
			break;
		case Client::SCTP_CONNECTED:
			state_name = "SCTP_CONNECTED.";
			break;
		case Client::SSL_HANDSHAKING:
			state_name = "SSL_HANDSHAKING";
			break;
		case Client::SSL_CONNECTED:
			state_name = "SSL_CONNECTED";
			break;
		case Client::SSL_SHUTDOWN:
			state_name = "SSL_SHUTDOWN";
			break;
		case Client::SCTP_SRV_INITIATED_SHUTDOWN:
			state_name = "SCTP_SRV_INITIATED_SHUTDOWN";
			break;
		case Client::PURGE:
			state_name = "PURGE";
			break;
		default:
			state_name = "UNKNOWN";
			break;
	}

	return out << state_name;
};

