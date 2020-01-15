#pragma once

#include "iclient.h"
#include "ssl_h.h"


class Client : public IClient {
public:
	explicit Client(struct socket* sock, SCTPServer& server);
	explicit Client(struct socket* sctp_sock, SCTPServer& s, size_t msg_size); 
	Client(const Client& oth) = delete;
	Client& operator=(const Client& oth) = delete;
	virtual ~Client();

	virtual void init() override;

	virtual void state(Client::State new_state) override;
	virtual IClient::State state() const noexcept override;

	virtual struct socket* socket() const override { return sock; };

	std::unique_ptr<Event> handle_message(const std::unique_ptr<SCTPMessage>&) override;

	virtual void send(const void* buf, size_t len) override;

	virtual void close() override;

	virtual std::vector<char>& sctp_msg_buff() override { return sctp_msg_buff_; };
	
	virtual std::string to_string() const override;

	friend bool operator== (const Client&, const Client&);
	friend bool operator!= (const Client&, const Client&);

	friend class SCTPServer;
private:
	struct socket* sock { nullptr };

	SCTPServer& server_;

	State state_ { NONE };

	size_t msg_size_ { 0 };

	std::vector<char> sctp_msg_buff_;
	std::vector<char> decrypted_msg_buff_;
	std::vector<char> encrypted_msg_buff_;	

	SSL* ssl = nullptr;
	BIO* output_bio = nullptr;
	BIO* input_bio = nullptr;

	virtual ssize_t send_raw(const void* buf, size_t len);

	std::unique_ptr<Event> handle_notification(const std::unique_ptr<SCTPMessage>& m);
	std::unique_ptr<Event> handle_data(const std::unique_ptr<SCTPMessage>& m);

	void handle_association_change_event(const struct sctp_assoc_change*, std::unique_ptr<Event>&) const;
	void handle_sender_dry_event(const struct sctp_sender_dry_event*, std::unique_ptr<Event>& e) const;
	void handle_peer_address_change_event(const struct sctp_paddr_change*) const;
	void handle_remote_error_event(const struct sctp_remote_error*) const;
	void handle_shutdown_event(const struct sctp_shutdown_event*) const;
	void handle_stream_reset_event(const struct sctp_stream_reset_event*) const;
	void handle_adaptation_indication(const struct sctp_adaptation_event*) const;
	void handle_send_failed_event(const struct sctp_send_failed_event*) const;
	void handle_stream_change_event(const struct sctp_stream_change_event*) const;

};


