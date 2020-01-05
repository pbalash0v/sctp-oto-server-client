#include <cassert>
#include <cstring>
#include <vector>
#include <sstream>
#include <map>
#include <errno.h>

#include "usrsctp.h"

#include "client.h"
#include "client_sctp_message.h"

#include "sctp_server.h"
#include "server_event.h"


#include <arpa/inet.h>

/* 
	Log macros depend on local object named cfg_.
	Getting it here explicitly.
	After this we can use log macros.
*/
#define ENABLE_DEBUG() std::shared_ptr<SCTPServer::Config> cfg_ = server_.cfg_

namespace {
	//constexpr auto BUFFER_SIZE = 1 << 16;

	std::map<IClient::State, std::string> state_names {
		{ IClient::NONE, "NONE" },
		{ IClient::SCTP_ACCEPTED, "SCTP_ACCEPTED" },
		{ IClient::SCTP_CONNECTED, "SCTP_CONNECTED"},
		{ IClient::SSL_HANDSHAKING, "SSL_HANDSHAKING"},
		{ IClient::SSL_CONNECTED, "SSL_CONNECTED"},
		{ IClient::SSL_SHUTDOWN, "SSL_SHUTDOWN"},
		{ IClient::SCTP_SHUTDOWN_CMPLT, "SCTP_SHUTDOWN_CMPLT"},
		{ IClient::SCTP_SRV_INITIATED_SHUTDOWN, "SCTP_SRV_INITIATED_SHUTDOWN"},
		{ IClient::PURGE, "PURGE"}
	};

	void inline _log_client_error_and_throw(const char* func, bool should_throw)
	{
		//ENABLE_DEBUG();

		std::string error { func };
		error += ": ";
		//error += to_string();
		error += " ";
		error += strerror(errno);
		//ERROR(error);
		if (should_throw) throw std::runtime_error(error);
	}


	// void inline log_client_error(const char* func)
	// {
	// 	_log_client_error_and_throw(func, false);
	// }


	void inline log_client_error_and_throw(const char* func)
	{
		_log_client_error_and_throw(func, true);
	}	
}

Client::Client(struct socket* sctp_sock, SCTPServer& s)
	: Client(sctp_sock, s, DEFAULT_SCTP_MESSAGE_SIZE_BYTES)
{};

Client::Client(struct socket* sctp_sock, SCTPServer& s, size_t message_size)
	: sock(sctp_sock), server_(s), msg_size_(message_size)
{
	sctp_msg_buff_.reserve(2*message_size);
	decrypted_msg_buff_.reserve(2*message_size);
	encrypted_msg_buff_.reserve(2*message_size);
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

ssize_t Client::send_raw(const void* buf, size_t len)
{
	ssize_t sent = -1;

	if (state() != IClient::SSL_CONNECTED) {
		sent = send(buf, len);
	} else {
		int written = SSL_write(ssl, buf, len);
		if (SSL_ERROR_NONE != SSL_get_error(ssl, written)) {
			log_client_error_and_throw("SSL_write");
		}

		encrypted_msg_buff_.clear();
		encrypted_msg_buff_.resize(BIO_ctrl_pending(output_bio));

		int read = BIO_read(output_bio,
					 encrypted_msg_buff_.data(), encrypted_msg_buff_.size());
		if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
			log_client_error_and_throw("BIO_read");
		}

		sent = send(encrypted_msg_buff_.data(), read);
	}

	if (sent < 0) {
		log_client_error_and_throw((std::string("usrsctp_sendv: ") + strerror(errno)).c_str());
	}

	return sent;
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


std::unique_ptr<Event> Client::handle_data(const std::unique_ptr<SCTPMessage>& m)
{
	ENABLE_DEBUG();

	TRACE(([&]()
	{
		return std::string("client data of size: ") +
				 std::to_string(m->size) + 
				 std::string(" for: ") + 
				 to_string();
	})());

	#define MAX_TLS_RECORD_SIZE (1 << 14)
	size_t outbuf_len = (state() != IClient::SSL_CONNECTED) ?
			MAX_TLS_RECORD_SIZE : m->size;

	decrypted_msg_buff_.clear();
	decrypted_msg_buff_.resize(outbuf_len);

	void* outbuf = decrypted_msg_buff_.data();

	auto evt = std::make_unique<Event>();
	evt->type = Event::CLIENT_STATE;

	switch (state()) {
	case IClient::SCTP_CONNECTED:
	{
		TRACE("IClient::SCTP_CONNECTED");

		// got client hello etc
		int written = BIO_write(input_bio, m->msg, m->size);
		if (SSL_ERROR_NONE != SSL_get_error(ssl, written)) {
			log_client_error_and_throw("BIO_write");
		}

		// we generate server hello etc
		int r = SSL_do_handshake(ssl);
		if (SSL_ERROR_WANT_READ != SSL_get_error(ssl, r)) {
			log_client_error_and_throw("SSL_do_handshake");
		}

		while (BIO_ctrl_pending(output_bio)) {
			TRACE("output BIO_ctrl_pending");

			int read = BIO_read(output_bio, outbuf, outbuf_len);
			if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
				log_client_error_and_throw("BIO_read");
			}

			ssize_t sent = send(outbuf, read);
			if (sent < 0) {
				log_client_error_and_throw("usrsctp_sendv");
			}
		}

		evt->client_state = IClient::SSL_HANDSHAKING;
	}
	break;

	case IClient::SSL_HANDSHAKING:
	{
		TRACE("IClient::SSL_HANDSHAKING");

		int written = BIO_write(input_bio, m->msg, m->size);
		if (SSL_ERROR_NONE != SSL_get_error(ssl, written)) {
			log_client_error_and_throw("BIO_write");
		}

		int r = SSL_do_handshake(ssl);

		if (not SSL_is_init_finished(ssl)) {
			if (SSL_ERROR_WANT_READ == SSL_get_error(ssl, r) and BIO_ctrl_pending(output_bio)) {
				int read = BIO_read(output_bio, outbuf, outbuf_len);
				if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
					log_client_error_and_throw("BIO_read");
				}

				ssize_t sent = send(outbuf, read);
				if (sent < 0) {
					log_client_error_and_throw("usrsctp_sendv");
				}
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(ssl, r) and BIO_ctrl_pending(output_bio)) {
				int read = BIO_read(output_bio, outbuf, outbuf_len);						
				if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
					log_client_error_and_throw("BIO_read");
				}

				ssize_t sent = send(outbuf, read);
				if (sent < 0) {
					log_client_error_and_throw("usrsctp_sendv");
				}

				evt->client_state = IClient::SSL_CONNECTED;

				// try {
				// 	server_.client_state(IClient::SSL_CONNECTED);
				// } catch (const std::runtime_error& exc) {
				// 	log_client_error_and_throw((std::string("set_state") + 
				// 		std::string(exc.what())).c_str());
				// }						
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(ssl, r) and not BIO_ctrl_pending(output_bio)) {
				evt->client_state = IClient::SSL_CONNECTED;

				// try {
				// 	server_.client_state(c, IClient::SSL_CONNECTED);
				// } catch (const std::runtime_error& exc) {
				// 	log_client_error_and_throw((std::string("client_state") + 
				// 		std::string(exc.what())).c_str());
				// }						
				break;
			}				
		} else {
			while (BIO_ctrl_pending(output_bio)) {
				TRACE("output BIO_ctrl_pending");

				int read = BIO_read(output_bio, outbuf, outbuf_len);
				if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
					log_client_error_and_throw("BIO_read");
				}

				ssize_t sent = send(outbuf, read);
				if (sent < 0) {
					log_client_error_and_throw("usrsctp_sendv");
				}
			}

			evt->client_state = IClient::SSL_CONNECTED;
			break;
		}
	}
	break;

	case IClient::SSL_CONNECTED:
	{
		TRACE(std::string("encrypted message length n: ") + std::to_string(m->size));

		size_t total_decrypted_message_size = 0;

		int written = BIO_write(input_bio, m->msg, m->size);
		if (SSL_ERROR_NONE != SSL_get_error(ssl, written)) {
			log_client_error_and_throw("BIO_write");
		}

		int read = -1;
		while (BIO_ctrl_pending(input_bio)) {
			read = SSL_read(ssl, static_cast<char*>(outbuf) + total_decrypted_message_size, MAX_TLS_RECORD_SIZE);
			TRACE(std::string("SSL read: ") + std::to_string(read));

			if (read == 0 and SSL_ERROR_ZERO_RETURN == SSL_get_error(ssl, read)) {
				DEBUG("SSL_ERROR_ZERO_RETURN");
				evt->client_state = IClient::SSL_SHUTDOWN;
				break;
			}

			if (read < 0 and SSL_ERROR_WANT_READ == SSL_get_error(ssl, read)) {
				TRACE("SSL_ERROR_WANT_READ");
				break;
			}

			if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
				log_client_error_and_throw("SSL_read");
			}

			total_decrypted_message_size += read;
		} 


		// if (read > 0) TRACE(([&]
		// {
		// 	char message[BUFFER_SIZE] = {'\0'};

		// 	char name[INET_ADDRSTRLEN] = {'\0'};

		// 	if (m->infotype == SCTP_RECVV_RCVINFO) {
		// 		snprintf(message, sizeof message,
		// 					"Msg %s of length %llu received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u.",
		// 					(char*) outbuf,
		// 					(unsigned long long) total_decrypted_message_size,
		// 					inet_ntop(AF_INET, &(m->addr.sin_addr), name, INET_ADDRSTRLEN),
		// 					ntohs(m->addr.sin_port),
		// 					m->rcv_info.recvv_rcvinfo.rcv_sid,	rcv_info.recvv_rcvinfo.rcv_ssn,
		// 					m->rcv_info.recvv_rcvinfo.rcv_tsn,
		// 					ntohl(rcv_info.recvv_rcvinfo.rcv_ppid), rcv_info.recvv_rcvinfo.rcv_context);
		// 	} else {
		// 		if (n < 30) 
		// 			snprintf(message, sizeof message, "Msg %s of length %llu received from %s:%u.",
		// 				(char*) outbuf,
		// 				(unsigned long long) total_decrypted_message_size,
		// 				inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN),
		// 				ntohs(addr.sin_port));
		// 		else 
		// 			snprintf(message, sizeof message, "Msg of length %llu received from %s:%u",
		// 				(unsigned long long) total_decrypted_message_size,
		// 				inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN),
		// 				ntohs(addr.sin_port));						
		// 	}

		// 	return std::string(message);
		// })());

		evt->type = Event::CLIENT_DATA;
		evt->client_state = IClient::SSL_CONNECTED;
		evt->client_data = std::make_unique<Data>(outbuf, total_decrypted_message_size);
	}
	break;

	case IClient::SSL_SHUTDOWN:
		break;

	default:
		log_client_error_and_throw("Unknown client state !");
	break;
	} //end of switch

	return evt;
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

bool operator== (const Client& c1, const Client& c2)
{
	return c1.sock == c2.sock;
}

bool operator!= (const Client& c1, const Client& c2)
{
	return not (c1 == c2);
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
	return out << state_names[s];
};

