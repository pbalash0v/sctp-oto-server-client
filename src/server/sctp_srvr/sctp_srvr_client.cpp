#include <cassert>
#include <cstring>
#include <sstream>

#include <errno.h>

#include "sctp_srvr_client.h"
#include "sctp_srvr.h"


Client::Client(struct socket* sctp_sock, SCTPServer& s) 
	: sock(sctp_sock), server(s) {

	ssl = SSL_new(server.ssl_obj_.ctx_);
	assert(ssl);

	output_bio = BIO_new(BIO_s_mem());
	assert(output_bio);

	input_bio = BIO_new(BIO_s_mem());
	assert(input_bio);
	  

	SSL_set_bio(ssl, input_bio, output_bio);

	SSL_set_accept_state(ssl);
};


void Client::set_state(Client::State new_state) {
	if (new_state != PURGE) {
		assert(new_state != state);
	}

	state = new_state;
	
	switch (new_state) {
		case SCTP_ACCEPTED:
			if (usrsctp_set_non_blocking(sock, 1) < 0) {
				throw std::runtime_error(strerror(errno));
			}
			if (usrsctp_set_upcall(sock, &SCTPServer::handle_upcall, &server)) {
				throw std::runtime_error(strerror(errno));
			}			
			break;
		case SCTP_CONNECTED:
			break;
		case PURGE:
			usrsctp_shutdown(sock, SHUT_RDWR);
			usrsctp_close(sock);
			break;

		default:
			break;
	}
}

Client::~Client() {
	SSL_free(ssl);
};

std::string Client::to_string() const {
	std::ostringstream oss;
	oss << this;
	return oss.str();
}

std::ostream& operator<<(std::ostream &out, const Client &c) {
	out << std::string("Client socket: ") << ((const void*) c.sock) << ", ";
	out << c.state;
	return out;
}

std::ostream& operator<<(std::ostream &out, const Client::State s) {
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
		case Client::PURGE:
			state_name = "PURGE";
			break;
		default:
			state_name = "UNKNOWN";
			break;
	}

	return out << state_name;
};

