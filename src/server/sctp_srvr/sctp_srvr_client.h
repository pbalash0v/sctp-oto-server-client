#pragma once

#include <iostream>

#include <usrsctp.h>

#include "ssl_h.h"


class SCTPServer;

struct Client {
   enum State {
   	NONE,
      SCTP_ACCEPTED,
      SCTP_CONNECTED,
      SSL_HANDSHAKING,
      SSL_CONNECTED,
		SSL_SHUTDOWN,
		PURGE
   };


	Client(struct socket* sock, SCTPServer& server);

	Client(const Client& oth) = delete;
	
	Client& operator=(const Client& oth) = delete;

	virtual ~Client();

	void set_state(Client::State new_state);

	std::string to_string() const;

	struct socket* sock = nullptr;

	SCTPServer& server;

	State state = NONE;

	SSL* ssl = nullptr;
	BIO* output_bio = nullptr;
	BIO* input_bio = nullptr;
};

std::ostream& operator<<(std::ostream &out, const Client &c);

std::ostream& operator<<(std::ostream &out, const Client::State s);
