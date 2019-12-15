#pragma once

#include <iostream>

#include "ssl_h.h"
#include "sctp_server_iclient.h"


class Client : public IClient {
public:
	Client(struct socket* sock, SCTPServer& server);

	Client(const Client& oth) = delete;
	
	Client& operator=(const Client& oth) = delete;

	virtual ~Client();

	virtual void init() override;

	virtual void set_state(Client::State new_state) override;

	virtual void* get_buffer() const override;

	virtual size_t get_buffer_size() const override;

	virtual std::string to_string() const override;

	friend std::ostream& operator<<(std::ostream &out, const Client &c);

	friend class SCTPServer;

private:

	std::unique_ptr<void, decltype(&std::free)> buff { nullptr, std::free };

};


