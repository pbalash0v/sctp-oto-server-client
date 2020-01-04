#include <cassert>
#include <cstring>
#include <vector>
#include <sstream>
#include <map>
#include <errno.h>

#include "usrsctp.h"

#include "client.h"
#include "sctp_server.h"


#include <arpa/inet.h>

/* 
	Log macros depend on local object named cfg_.
	Getting it here explicitly.
	After this we can use log macros.
*/
#define ENABLE_DEBUG() std::shared_ptr<SCTPServer::Config> cfg_ = server_.cfg_

namespace {
	std::map<IClient::State, std::string> state_names {
		{ IClient::NONE, "NONE" },
		{ IClient::SCTP_ACCEPTED, "SCTP_ACCEPTED" },
		{ IClient::SCTP_CONNECTED, "SCTP_CONNECTED"},
		{ IClient::SSL_HANDSHAKING, "SSL_HANDSHAKING"},
		{ IClient::SSL_CONNECTED, "SSL_CONNECTED"},
		{ IClient::SSL_SHUTDOWN, "SSL_SHUTDOWN"},
		{ IClient::SCTP_SRV_INITIATED_SHUTDOWN, "SCTP_SRV_INITIATED_SHUTDOWN"},
		{ IClient::PURGE, "PURGE"}
	};
}

Client::Client(struct socket* sctp_sock, SCTPServer& s)
	: Client(sctp_sock, s, DEFAULT_SCTP_MESSAGE_SIZE_BYTES)
{};

Client::Client(struct socket* sctp_sock, SCTPServer& s, size_t message_size)
	: sock(sctp_sock), server_(s), msg_size_(message_size)
{
	sctp_msg_buff().reserve(2*message_size);
	decrypted_msg_buff().reserve(2*message_size);
	encrypted_msg_buff().reserve(2*message_size);
};

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
}


void Client::state(Client::State new_state)
{
	ENABLE_DEBUG();

	TRACE_func_entry();

	if (new_state == PURGE and state_ == PURGE) {
		WARNING("PURGE to PURGE transition.");
		return;
	}

	assert(new_state != state_);

	switch (new_state) {
	case SCTP_ACCEPTED:
	{
		uint16_t event_types[] = {	SCTP_ASSOC_CHANGE,
                          			SCTP_PEER_ADDR_CHANGE,
                          			SCTP_REMOTE_ERROR,
                          			SCTP_SHUTDOWN_EVENT,
                          			SCTP_ADAPTATION_INDICATION,
                          			SCTP_PARTIAL_DELIVERY_EVENT,
                          			SCTP_SENDER_DRY_EVENT
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

		auto bufsize = 1024*1024; //this should depend on cfg_->message_size
		if (usrsctp_setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(int))) {
			ERROR("usrsctp_setsockopt SO_RCVBUF: " + to_string());
			throw std::runtime_error("setsockopt: rcvbuf" + std::string(strerror(errno)));
		}

		if (usrsctp_setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(int))) {
			ERROR("usrsctp_setsockopt SO_SNDBUF: " + to_string());
			throw std::runtime_error("setsockopt: sndbuf" + std::string(strerror(errno)));
		}
		
		if (usrsctp_set_upcall(sock, &SCTPServer::handle_client_upcall, &server_)) {
			ERROR("usrsctp_set_upcall for " + to_string());
			throw std::runtime_error("usrsctp_set_upcall: " + std::string(strerror(errno)));
		}
		
		sctp_paddrparams params;
		memset(&params, 0, sizeof params);
		params.spp_address.ss_family = AF_INET;
		params.spp_flags = SPP_PMTUD_DISABLE;
		params.spp_pathmtu = 1280;

		if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &params, sizeof(params))) {
			ERROR("usrsctp_setsockopt SCTP_PEER_ADDR_PARAMS " + to_string());
			throw std::runtime_error("setsockopt SCTP_PEER_ADDR_PARAMS: " + std::string(strerror(errno)));
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

	TRACE(state_names[state_] + " -> " + state_names[new_state]);

	state_ = new_state;

	TRACE_func_left();
}


IClient::State Client::state() const noexcept
{
	return state_;
}

size_t Client::send(const void* buf, size_t len)
{
	ENABLE_DEBUG();

	// addrs - NULL for connected socket
	// addrcnt: Number of addresses.
	// As at most one address is supported, addrcnt is 0 if addrs is NULL and 1 otherwise.	
	int sent = usrsctp_sendv(sock, buf, len,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
	if (sent < 0) {
		WARNING("usrsctp_sendv: " + std::string(strerror(errno)));
	}
	
	TRACE("Sent: " + std::to_string(sent) + std::string(". Errno: ") + std::string(strerror(errno)));

	return sent;
};

void Client::close()
{
	usrsctp_close(sock);
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
	out << std::string("Client [socket: ") << (static_cast<void*>(c.socket())) << ", ";
	out << c.state();
	out << std::string("]");
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
			state_name = "SCTP_CONNECTED";
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

