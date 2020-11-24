#include <cassert>
#include <cstring>
#include <vector>
#include <sstream>
#include <map>
#include <errno.h>
#include <arpa/inet.h>

#include "usrsctp.h"

#include "client.h"
#include "client_sctp_message.h"

#include "sctp_server.h"
#include "server_event.h"
#include "logging.h"
#include "log_level.h"
#include "sctp_data.h"
#include "ssl_h.h"



/* 
	Log macros depend on local object named cfg_.
	Getting it here explicitly.
	After this we can use log macros.
*/
#define ENABLE_LOGGING() std::shared_ptr<SCTPServer::Config> cfg_ = server_.cfg_

namespace {
	constexpr auto BUFFER_SIZE = 1 << 16;

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

	std::map<uint16_t, std::string> notification_names {
		{ SCTP_ASSOC_CHANGE, "SCTP_ASSOC_CHANGE" },
		{ SCTP_PEER_ADDR_CHANGE, "SCTP_PEER_ADDR_CHANGE" },
		{ SCTP_REMOTE_ERROR, "SCTP_REMOTE_ERROR"},
		{ SCTP_SEND_FAILED, "SCTP_SEND_FAILED"},
		{ SCTP_SHUTDOWN_EVENT, "SCTP_SHUTDOWN_EVENT"},
		{ SCTP_ADAPTATION_INDICATION, "SCTP_ADAPTATION_INDICATION"},
		{ SCTP_PARTIAL_DELIVERY_EVENT, "SCTP_PARTIAL_DELIVERY_EVENT"},
		{ SCTP_AUTHENTICATION_EVENT, "SCTP_AUTHENTICATION_EVENT"},
		{ SCTP_SENDER_DRY_EVENT, "SCTP_SENDER_DRY_EVENT"},
		{ SCTP_STREAM_RESET_EVENT, "SCTP_STREAM_RESET_EVENT"},
		{ SCTP_NOTIFICATIONS_STOPPED_EVENT, "SCTP_NOTIFICATIONS_STOPPED_EVENT"},
		{ SCTP_ASSOC_RESET_EVENT, "SCTP_ASSOC_RESET_EVENT"},
		{ SCTP_STREAM_CHANGE_EVENT, "SCTP_STREAM_CHANGE_EVENT"},
		{ SCTP_SEND_FAILED_EVENT, "SCTP_SEND_FAILED_EVENT"}
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

Client::~Client()
{
	if (nullptr != ssl) SSL_free(ssl);
};

void Client::init()
{
	ssl = SSL_new(server_.ssl_obj_->ctx_);
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
	ENABLE_LOGGING();

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

/*
	Public send
*/
void Client::send(const void* buf, size_t len)
{
	ssize_t sent = -1;

	if (state() != IClient::SSL_CONNECTED) {
		sent = send_raw(buf, len);
	} else {
		int written = SSL_write(ssl, buf, len);
		if (SSL_ERROR_NONE != SSL_get_error(ssl, written)) {
			log_client_error_and_throw("SSL_write");
		}

		encrypted_msg_buff_.clear();
		encrypted_msg_buff_.resize(BIO_ctrl_pending(output_bio));

		int read = BIO_read(output_bio, encrypted_msg_buff_.data(),
				encrypted_msg_buff_.size());
		if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
			log_client_error_and_throw("BIO_read");
		}

		sent = send_raw(encrypted_msg_buff_.data(), read);
	} 

	if (sent < 0) {
		log_client_error_and_throw((std::string("send: ") + strerror(errno)).c_str());
	}
}

ssize_t Client::send_raw(const void* buf, size_t len)
{
	ENABLE_LOGGING();

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

std::unique_ptr<Event> Client::handle_message(const std::unique_ptr<SCTPMessage>& m)
{
	return (m->type == SCTPMessage::DATA) ? handle_data(m) : handle_notification(m);
}


std::unique_ptr<Event> Client::handle_data(const std::unique_ptr<SCTPMessage>& m)
{
	ENABLE_LOGGING();

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

	auto evt = std::make_unique<Event>(*m);

	TRACE(state_names[state_]);
	switch (state_) {
	case IClient::SCTP_CONNECTED:
	{
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
			//TRACE("output BIO_ctrl_pending");

			int read = BIO_read(output_bio, outbuf, outbuf_len);
			if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
				log_client_error_and_throw("BIO_read");
			}

			send(outbuf, read);
		}

		evt->type = Event::CLIENT_STATE;
		evt->client_state = IClient::SSL_HANDSHAKING;
	}
	break;

	case IClient::SSL_HANDSHAKING:
	{
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

				send(outbuf, read);
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(ssl, r) and BIO_ctrl_pending(output_bio)) {
				int read = BIO_read(output_bio, outbuf, outbuf_len);						
				if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
					log_client_error_and_throw("BIO_read");
				}

				send(outbuf, read);

				evt->type = Event::CLIENT_STATE;
				evt->client_state = IClient::SSL_CONNECTED;
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(ssl, r) and not BIO_ctrl_pending(output_bio)) {
				evt->type = Event::CLIENT_STATE;
				evt->client_state = IClient::SSL_CONNECTED;
				break;
			}				
		} else {
			while (BIO_ctrl_pending(output_bio)) {
				TRACE("output BIO_ctrl_pending");

				int read = BIO_read(output_bio, outbuf, outbuf_len);
				if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
					log_client_error_and_throw("BIO_read");
				}

				send(outbuf, read);
			}

			evt->type = Event::CLIENT_STATE;
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
		evt->client_data = std::make_unique<sctp::Data>(outbuf, total_decrypted_message_size);
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


/*
	Functions to handle assoc notifications
*/
void Client::handle_association_change_event(const struct sctp_assoc_change* sac,
	std::unique_ptr<Event>& e) const
{
	ENABLE_LOGGING();
	unsigned int i, n;

	TRACE(([&]
		{
			std::string message { "Association change " };

			switch (sac->sac_state) {
				case SCTP_COMM_UP:
					message += "SCTP_COMM_UP";
					break;
				case SCTP_COMM_LOST:
					message += "SCTP_COMM_LOST";
					break;
				case SCTP_RESTART:
					message += "SCTP_RESTART";
					break;
				case SCTP_SHUTDOWN_COMP:
					message += "SCTP_SHUTDOWN_COMP";
					break;
				case SCTP_CANT_STR_ASSOC:
					message += "SCTP_CANT_STR_ASSOC";
					break;
				default:
					message += "UNKNOWN";
					break;
			}

			message += ", streams (in/out) = (";
			message += std::to_string(sac->sac_inbound_streams);
			message += "/";
			message += std::to_string(sac->sac_outbound_streams);
			message += ")";

			n = sac->sac_length - sizeof(struct sctp_assoc_change);

			if (((sac->sac_state == SCTP_COMM_UP) or
			     (sac->sac_state == SCTP_RESTART)) and (n > 0)) {
				message += ", supports";
				for (i = 0; i < n; i++) {
					switch (sac->sac_info[i]) {
					case SCTP_ASSOC_SUPPORTS_PR:
						message += " PR";
						break;
					case SCTP_ASSOC_SUPPORTS_AUTH:
						message += " AUTH";
						break;
					case SCTP_ASSOC_SUPPORTS_ASCONF:
						message += " ASCONF";
						break;
					case SCTP_ASSOC_SUPPORTS_MULTIBUF:
						message += " MULTIBUF";
						break;
					case SCTP_ASSOC_SUPPORTS_RE_CONFIG:
						message += " RE-CONFIG";
						break;
					default:
						message += " UNKNOWN(0x";
						message += std::to_string(sac->sac_info[i]);
						message += ")";
						break;
					}
				}
			} else if (((sac->sac_state == SCTP_COMM_LOST) or
			            (sac->sac_state == SCTP_CANT_STR_ASSOC)) and (n > 0)) {
				message += ", ABORT =";
				for (i = 0; i < n; i++) {
					message += " 0x";
					message += std::to_string(sac->sac_info[i]);
				}
			}

			message += ".";

			return message;
		})()
	);

	/*
		Association change handling
	*/

	switch (sac->sac_state) {
		case SCTP_COMM_UP:
			e->type = Event::CLIENT_STATE;
			e->client_state = IClient::SCTP_CONNECTED;
			DEBUG("SCTP_COMM_UP: " + to_string());
			break;
		case SCTP_COMM_LOST:
			break;
		case SCTP_RESTART:
			break;
		case SCTP_SHUTDOWN_COMP:
			e->type = Event::CLIENT_STATE;
			e->client_state = IClient::SCTP_SHUTDOWN_CMPLT;
			DEBUG("SCTP_SHUTDOWN_COMP: " + to_string());
			break;
		case SCTP_CANT_STR_ASSOC:
			break;
		default:
			break;
	}

	return;
}

void Client::handle_peer_address_change_event(const struct sctp_paddr_change* spc) const
{
	ENABLE_LOGGING();

	char addr_buf[INET6_ADDRSTRLEN];
	const char* addr;
	char buf[BUFFER_SIZE] = { '\0' };
	struct sockaddr_in *sin;
	struct sockaddr_in6* sin6;
	struct sockaddr_conn* sconn;

	switch (spc->spc_aaddr.ss_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)&spc->spc_aaddr;
			addr = inet_ntop(AF_INET, &sin->sin_addr, addr_buf, INET_ADDRSTRLEN);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&spc->spc_aaddr;
			addr = inet_ntop(AF_INET6, &sin6->sin6_addr, addr_buf, INET6_ADDRSTRLEN);
			break;
		case AF_CONN:
			sconn = (struct sockaddr_conn *)&spc->spc_aaddr;
			snprintf(addr_buf, INET6_ADDRSTRLEN, "%p", sconn->sconn_addr);
			addr = addr_buf;
			break;
		default:
			snprintf(addr_buf, INET6_ADDRSTRLEN, "Unknown family %d", spc->spc_aaddr.ss_family);
			addr = addr_buf;
			break;
	}

	int written = snprintf(buf, sizeof buf, "Peer address %s is now ", addr);

	switch (spc->spc_state) {
		case SCTP_ADDR_AVAILABLE:
			written += snprintf(buf + written , sizeof(buf) - written, "SCTP_ADDR_AVAILABLE");
			break;
		case SCTP_ADDR_UNREACHABLE:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_UNREACHABLE");
			break;
		case SCTP_ADDR_REMOVED:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_REMOVED");
			break;
		case SCTP_ADDR_ADDED:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_ADDED");
			break;
		case SCTP_ADDR_MADE_PRIM:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_MADE_PRIM");
			break;
		case SCTP_ADDR_CONFIRMED:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_CONFIRMED");
			break;
		default:
			written += snprintf(buf + written,  sizeof(buf) - written, "UNKNOWN");
			break;
	}

	snprintf(buf + written, sizeof(buf) - written, " (error = 0x%08x).", spc->spc_error);

	DEBUG(buf);
	return;
}

void Client::handle_send_failed_event(const struct sctp_send_failed_event* ssfe) const
{
	ENABLE_LOGGING();
	size_t i, n;

	char buf[BUFFER_SIZE] = { '\0' };

	int written	= 0;
	if (ssfe->ssfe_flags & SCTP_DATA_UNSENT) {
		written += snprintf(buf + written, sizeof(buf)-written, "Unsent ");
	}

	if (ssfe->ssfe_flags & SCTP_DATA_SENT) {
		written += snprintf(buf + written, sizeof(buf)-written, "Sent ");
	}

	if (ssfe->ssfe_flags & ~(SCTP_DATA_SENT | SCTP_DATA_UNSENT)) {
		written += snprintf(buf + written, sizeof(buf)-written, "(flags = %x) ", ssfe->ssfe_flags);
	}

	written += snprintf(buf + written, sizeof(buf)-written,
			 "message with PPID = %u, SID = %u, flags: 0x%04x due to error = 0x%08x",
	       ntohl(ssfe->ssfe_info.snd_ppid), ssfe->ssfe_info.snd_sid,
	       ssfe->ssfe_info.snd_flags, ssfe->ssfe_error);

	n = ssfe->ssfe_length - sizeof(struct sctp_send_failed_event);
	for (i = 0; i < n; i++) {
		written += snprintf(buf + written, sizeof(buf)-written, " 0x%02x", ssfe->ssfe_data[i]);
	}

	written += snprintf(buf + written, sizeof(buf)-written, ".\n");
	
	DEBUG(buf);
	return;
}

void Client::handle_adaptation_indication(const struct sctp_adaptation_event* sai) const
{
	ENABLE_LOGGING();

	char buf[BUFFER_SIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Adaptation indication: %x.\n", sai-> sai_adaptation_ind);
	DEBUG(buf);
	return;
}

void Client::handle_shutdown_event(const struct sctp_shutdown_event*) const
{
	ENABLE_LOGGING();

	char buf[BUFFER_SIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Shutdown event.");
	DEBUG(buf);
	/* XXX: notify all channels. */
	return;
}

void Client::handle_stream_reset_event(const struct sctp_stream_reset_event* strrst) const
{
	ENABLE_LOGGING();

	uint32_t n, i;

	n = (strrst->strreset_length - sizeof(struct sctp_stream_reset_event)) / sizeof(uint16_t);

	char buf[BUFFER_SIZE] = { '\0' };
	int written = snprintf(buf, sizeof buf, "Stream reset event: flags = %x, ", strrst->strreset_flags);

	if (strrst->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) {
		if (strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
			written += snprintf(buf + written, sizeof(buf)-written, "incoming/");
		}
		written += snprintf(buf + written, sizeof(buf)-written, "incoming ");
	}
	if (strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
		written += snprintf(buf + written, sizeof(buf)-written, "outgoing ");
	}

	written += snprintf(buf + written, sizeof(buf)-written, "stream ids = ");
	for (i = 0; i < n; i++) {
		if (i > 0) {
			written += snprintf(buf + written, sizeof(buf)-written, ", ");
		}
		written += snprintf(buf + written, sizeof(buf)-written, "%d", strrst->strreset_stream_list[i]);
	}

	written += snprintf(buf + written, sizeof(buf)-written, ".\n");

	DEBUG(buf);
	return;
}

void Client::handle_stream_change_event(const struct sctp_stream_change_event* strchg) const
{
	ENABLE_LOGGING();

	char buf[BUFFER_SIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Stream change event: streams (in/out) = (%u/%u), flags = %x.\n",
	       strchg->strchange_instrms, strchg->strchange_outstrms, strchg->strchange_flags);

	DEBUG(buf);
	return;
}

void Client::handle_remote_error_event(const struct sctp_remote_error* sre) const
{
	ENABLE_LOGGING();

	size_t i, n;

	n = sre->sre_length - sizeof(struct sctp_remote_error);

	int written = 0;
	char buf[BUFFER_SIZE] = { '\0' };
	written = snprintf(buf, sizeof buf, "Remote Error (error = 0x%04x): ", sre->sre_error);
	for (i = 0; i < n; i++) {
		written += snprintf(buf + written, sizeof buf - written, " 0x%02x", sre-> sre_data[i]);
	}

	WARNING(std::string(buf) + ".\n");
	return;
}

void Client::handle_sender_dry_event(const struct sctp_sender_dry_event*,
	std::unique_ptr<Event>& e) const
{
	e->type = Event::CLIENT_SEND_POSSIBLE;
}

std::unique_ptr<Event> Client::handle_notification(const std::unique_ptr<SCTPMessage>& m)
{
	ENABLE_LOGGING();
	TRACE_func_entry();

	union sctp_notification* notif = static_cast<union sctp_notification*>(m->msg);
	size_t n = m->size;

	if (notif->sn_header.sn_length != (uint32_t) n) {
		WARNING("notif->sn_header.sn_length != n");
		throw std::runtime_error("notif->sn_header.sn_length != n");
	}

	TRACE("handle_notification: " + notification_names[notif->sn_header.sn_type]);

	auto evt = std::make_unique<Event>(*m);
	evt->client_state = state_;

	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		handle_association_change_event(&(notif->sn_assoc_change), evt);
		break;
	case SCTP_PEER_ADDR_CHANGE:
		handle_peer_address_change_event(&(notif->sn_paddr_change));
		break;
	case SCTP_REMOTE_ERROR:
		handle_remote_error_event(&(notif->sn_remote_error));
		break;
	case SCTP_SHUTDOWN_EVENT:
		handle_shutdown_event(&(notif->sn_shutdown_event));
		break;
	case SCTP_ADAPTATION_INDICATION:
		handle_adaptation_indication(&(notif->sn_adaptation_event));
		break;
	case SCTP_SENDER_DRY_EVENT:
		handle_sender_dry_event(&(notif->sn_sender_dry_event), evt);
		break;
	case SCTP_SEND_FAILED_EVENT:
		handle_send_failed_event(&(notif->sn_send_failed_event));
		break;
	case SCTP_STREAM_RESET_EVENT:
		handle_stream_reset_event(&(notif->sn_strreset_event));
		break;
	case SCTP_STREAM_CHANGE_EVENT:
		handle_stream_change_event(&(notif->sn_strchange_event));
		break;
	case SCTP_NOTIFICATIONS_STOPPED_EVENT:
	case SCTP_ASSOC_RESET_EVENT:
	case SCTP_PARTIAL_DELIVERY_EVENT:
	case SCTP_AUTHENTICATION_EVENT:
		break;		
	default:
		ERROR("Unknown notification type !");
		break;
	}

	TRACE_func_left();

	return evt;
}


std::string Client::to_string() const
{
	std::ostringstream oss;

	oss << std::string("Client [socket: ");
	oss << (static_cast<void*>(socket())) << ", ";
	oss << state_names[state_];
	oss << std::string("]");

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


std::ostream& operator<<(std::ostream &out, const Client::State s)
{
	return out << state_names[s];
};

