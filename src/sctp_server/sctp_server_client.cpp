#include <cassert>
#include <cstring>
#include <sstream>

#include <errno.h>

#include <usrsctp.h>

#include "sctp_server_client.h"
#include "sctp_server.h"

/* 
	Log macros depend on local object named cfg_.
	Getting it here explicitly.
	After this we can use log macros.
*/
#define ENABLE_DEBUG() std::shared_ptr<SCTPServer::Config> cfg_ = server_.cfg_


Client::Client(struct socket* sctp_sock, SCTPServer& s)
	: Client(sctp_sock, s, DEFAULT_SCTP_MESSAGE_SIZE_BYTES) {};

Client::Client(struct socket* sctp_sock, SCTPServer& s, size_t message_size)
	: IClient(sctp_sock, s), message_size_(message_size) {};

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

	buff = ([&]()
	{
		void* buf_ = calloc(message_size_, sizeof(char));
		if (not buf_) throw std::runtime_error("Calloc in init() failed.");

		available_buffer_space = message_size_;
		return std::unique_ptr<void, decltype(&std::free)> (buf_, std::free);
	})();
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

	state_ = new_state;
	
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

IClient::State Client::state() const noexcept
{
	return state_;
}


void* Client::get_writable_buffer() const
{
	return static_cast<char*>(buff.get()) + get_buffered_data_size();
}

void* Client::get_message_buffer() const
{
	return buff.get();
}

void Client::realloc_buffer()
{
	ENABLE_DEBUG();
	TRACE_func_entry();

	void* new_buff = realloc(buff.get(), available_buffer_space + message_size_);
	if (new_buff) {
		available_buffer_space += message_size_;
		if (new_buff != buff.get()) {
			buff.release();
			buff.reset(new_buff);
		}
		buffered_data_size += message_size_;
		//memset(get_writable_buffer(), 0, CLIENT_BUFFERSIZE);
		buffer_needs_realloc = true;
	} else {
		throw std::runtime_error("Realloc in realloc_buffer() failed.");
	}

	TRACE("available_buffer_space: " + std::to_string(available_buffer_space));

	TRACE_func_left();
}

void Client::reset_buffer()
{
	ENABLE_DEBUG();
	TRACE_func_entry();

	if (buffer_needs_realloc) {
		DEBUG("reallocing buffer");
		void* new_buff = realloc(buff.get(), message_size_);

		if (not new_buff) {
			throw std::runtime_error("Realloc in reset_buffer() failed.");
		}

		if (new_buff != buff.get()) buff.reset(new_buff);
	}

	memset(buff.get(), 0, message_size_);
	available_buffer_space = message_size_;
	buffered_data_size = 0;
	buffer_needs_realloc = false;

	TRACE_func_left();
}



size_t Client::get_buffered_data_size() const noexcept
{
	return buffered_data_size;
}
	

size_t Client::get_writable_buffer_size() const noexcept
{
	return message_size_;
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
	out << std::string("Client: socket: ") << (static_cast<const void*>(c.sock)) << ", ";
	out << c.state_;
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

