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

	virtual void state(Client::State new_state) override;

	virtual IClient::State state() const noexcept override;

	virtual void* get_writable_buffer() const override;

	virtual void realloc_buffer() override;

	virtual void reset_buffer() override;

	virtual void* get_message_buffer() const override;

	virtual size_t get_writable_buffer_size() const noexcept override;

	virtual size_t get_buffered_data_size() const noexcept override;

	virtual std::string to_string() const override;

	friend std::ostream& operator<<(std::ostream &out, const Client &c);

	friend class SCTPServer;

private:

	State state_ = NONE;

	size_t buffered_data_size { 0 };

	size_t available_buffer_space { 0 };

	bool buffer_needs_realloc { false };

	std::unique_ptr<void, decltype(&std::free)> buff { nullptr, std::free };

};


