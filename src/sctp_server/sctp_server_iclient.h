#pragma once

#include <iostream>
#include <memory>

#include "ssl_h.h"


class SCTPServer;

#define BUFFERSIZE (1<<16)

class IClient {
public:
   enum State {
   	NONE,
      SCTP_ACCEPTED,
      SCTP_CONNECTED,
      SSL_HANDSHAKING,
      SSL_CONNECTED,
		SSL_SHUTDOWN,
		SCTP_SRV_INITIATED_SHUTDOWN,
		PURGE
   };

   struct Data {
   	Data(const void*, size_t);

		Data(const Data& oth) = delete;
	
		Data& operator=(const Data& oth) = delete;

		virtual ~Data();

   	void* data { nullptr };
   	size_t size { 0 };
	};

	IClient(struct socket* s, SCTPServer& srv) : sock(s), server_(srv) {};

	virtual ~IClient() {};

	virtual void init() = 0;
	virtual void set_state(IClient::State) = 0;
	virtual std::string to_string() const = 0;

	virtual void* get_buffer() const = 0;
	virtual size_t get_buffer_size() const = 0;

	struct socket* sock = nullptr;

	SCTPServer& server_;

	State state = NONE;

	SSL* ssl = nullptr;
	BIO* output_bio = nullptr;
	BIO* input_bio = nullptr;
	
	friend std::ostream& operator<<(std::ostream &out, const IClient::State s);
	friend class SCTPServer;
};


