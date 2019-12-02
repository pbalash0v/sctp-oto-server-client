#pragma once

#include <iostream>

#include <usrsctp.h>

#include "ssl_h.h"

class SCTPServer;


class IClient {
public:
   enum State {
   	NONE,
      SCTP_ACCEPTED,
      SCTP_CONNECTED,
      SSL_HANDSHAKING,
      SSL_CONNECTED,
		SSL_SHUTDOWN,
		PURGE
   };

	IClient(struct socket* s, SCTPServer& srv)
	 : sock(s), server_(srv) {};

	virtual ~IClient() {};

	virtual void init() = 0;
	virtual void set_state(IClient::State) = 0;
	virtual std::string to_string() const = 0;

	struct socket* sock = nullptr;

	SCTPServer& server_;

	State state = NONE;

	SSL* ssl = nullptr;
	BIO* output_bio = nullptr;
	BIO* input_bio = nullptr;
	
	friend std::ostream& operator<<(std::ostream &out, const IClient::State s);
	friend class SCTPServer;
};



class Client : public IClient {
public:
	Client(struct socket* sock, SCTPServer& server);

	Client(const Client& oth) = delete;
	
	Client& operator=(const Client& oth) = delete;

	virtual ~Client();

	virtual void init();

	virtual void set_state(Client::State new_state);

	virtual std::string to_string() const;

	friend std::ostream& operator<<(std::ostream &out, const Client &c);

	friend class SCTPServer;


private:

};


