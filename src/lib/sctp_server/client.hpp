#pragma once

#include <openssl/ssl.h>

#include "sctp_server.hpp"

namespace sctp
{
	class ServerImpl;
	struct ServerEvent;
}

class Client : public sctp::Server::IClient
{
public:
	explicit Client(struct socket* sock, sctp::ServerImpl& server);
	explicit Client(struct socket* sctp_sock, sctp::ServerImpl& s, size_t msg_size);
	Client(const Client& oth) = delete;
	Client& operator=(const Client& oth) = delete;
	virtual ~Client();


	virtual void state(IClient::State new_state) override;

	virtual IClient::State state() const noexcept override
	{
		return state_;
	}

	virtual struct socket* socket() const override { return sock; };

	sctp::ServerEvent handle_message(const std::unique_ptr<sctp::Message>&) override;

	virtual void send(const void* buf, size_t len) override;

	virtual void close() override;

	virtual std::vector<char>& sctp_msg_buff() override { return sctp_msg_buff_; };
	
	virtual std::string to_string() const override;

	friend bool operator== (const Client&, const Client&);
	friend bool operator!= (const Client&, const Client&);

	friend class sctp::Server;

private:
	struct socket* sock {nullptr};

	sctp::ServerImpl& server_;

	IClient::State state_ {IClient::State::NONE};

	size_t msg_size_ {};

	std::vector<char> sctp_msg_buff_;
	std::vector<char> decrypted_msg_buff_;
	std::vector<char> encrypted_msg_buff_;	

	SSL* ssl {nullptr};
	BIO* output_bio {nullptr};
	BIO* input_bio {nullptr};

private:
	void init(SSL_CTX*);

	ssize_t send_raw(const void* buf, size_t len);

	sctp::ServerEvent handle_notification(const std::unique_ptr<sctp::Message>& m);
	sctp::ServerEvent handle_data(const std::unique_ptr<sctp::Message>& m);

	void handle_association_change_event(const struct sctp_assoc_change*, sctp::ServerEvent&) const;
	void handle_sender_dry_event(const struct sctp_sender_dry_event*, sctp::ServerEvent&) const;
	void handle_peer_address_change_event(const struct sctp_paddr_change*) const;
	void handle_remote_error_event(const struct sctp_remote_error*) const;
	void handle_shutdown_event(const struct sctp_shutdown_event*) const;
	void handle_stream_reset_event(const struct sctp_stream_reset_event*) const;
	void handle_adaptation_indication(const struct sctp_adaptation_event*) const;
	void handle_send_failed_event(const struct sctp_send_failed_event*) const;
	void handle_stream_change_event(const struct sctp_stream_change_event*) const;
};


