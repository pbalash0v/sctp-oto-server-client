#pragma once

#include <iostream>

#include "ssl_h.h"
#include "sctp_server_iclient.h"


class Client : public IClient {
public:
	Client(struct socket* sock, SCTPServer& server);
	
	Client(struct socket* sctp_sock, SCTPServer& s, size_t msg_size); 

	Client(const Client& oth) = delete;
	
	Client& operator=(const Client& oth) = delete;

	virtual ~Client();

	virtual void init() override;

	virtual void state(Client::State new_state) override;

	virtual IClient::State state() const noexcept override;

	virtual std::vector<char>& sctp_msg_buff() override { return sctp_msg_buff_; };

	virtual std::vector<char>& decrypted_msg_buff() override { return decrypted_msg_buff_; };

	virtual std::string to_string() const override;

	friend std::ostream& operator<<(std::ostream &out, const Client &c);

	friend class SCTPServer;

private:

	State state_ = NONE;

	size_t msg_size_ = { 0 };

	std::vector<char> sctp_msg_buff_;
	std::vector<char> decrypted_msg_buff_;	
};


