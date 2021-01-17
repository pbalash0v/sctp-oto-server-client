#ifndef __sctp_client_impl_hpp__
#define __sctp_client_impl_hpp__

#include <thread>
#include <functional>
#include <string>
#include <atomic>
#include <unordered_map>
#include <vector>
#include <cstring>

#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <log_level.hpp>

#include "sync_queue.hpp"

#include "sctp_client.hpp"
#include "sctp_client.hpp"


namespace sctp
{
class SSLWrapper;


class ClientImpl final
{
public:
	explicit ClientImpl(std::shared_ptr<sctp::Client::Config>);
	ClientImpl(const ClientImpl&) = delete;
	ClientImpl& operator=(const ClientImpl&) = delete;
	ClientImpl(ClientImpl&&) = default;
	ClientImpl& operator=(ClientImpl&&) = default;

	~ClientImpl();

	/*
		Getter for cfg object
	*/
	std::shared_ptr<Client::Config> cfg() { return cfg_; };

	/* 
		Starts client. Doesn't block.
	*/
	void operator()();

	bool connected() const noexcept { return state_ == Client::State::SSL_CONNECTED; };

	ssize_t send(const void*, size_t);

	void stop();

	friend class ::sctp::Client;

	friend std::ostream& operator<<(std::ostream& out, const Client& cli);

private:
	std::shared_ptr<Client::Config> cfg_;

	std::unique_ptr<SSLWrapper> ssl_obj_ {nullptr};
	SSL* ssl_ {nullptr};
	BIO* output_bio_ {nullptr};
	BIO* input_bio_ {nullptr};

	std::unique_ptr<std::atomic_bool> usrsctp_lib_initialized_ptr_ {std::make_unique<std::atomic_bool>(false)};
	static inline std::unique_ptr<std::atomic_size_t> number_of_instances_ptr_ {std::make_unique<std::atomic_size_t>()};

	std::unique_ptr<std::atomic_bool> sender_dry_ptr_ {std::make_unique<std::atomic_bool>(false)};;

	Client::State state_ {Client::State::NONE};

	int udp_sock_fd_ {-1};
	uint16_t bound_udp_encaps_port_ {};
	struct socket* sock_ {nullptr};

	std::unique_ptr<SyncQueue<std::unique_ptr<std::vector<char>>>> raw_udp_data_ {nullptr};
	std::vector<char> sctp_msg_buff_;
	std::vector<char> decrypted_msg_buff_;
	std::vector<char> encrypted_msg_buff_;

	std::thread udp_recv_thr_;
	std::thread udp_data_thr_;

private:
	void init();

	void init_local_UDP();
	void init_remote_UDP();
	void init_usrsctp_lib();
	void init_SCTP();

	void udp_recv_loop();
	void handle_raw_udp_data_loop();

	ssize_t send_raw(const void*, size_t);

	static int conn_output(void*, void*, size_t, uint8_t, uint8_t);
	static void handle_upcall(struct socket*, void*, int);

	void handle_server_data(void*, ssize_t, const struct sockaddr_in&,
		const struct sctp_recvv_rn&, unsigned int);

	void handle_notification(union sctp_notification*, size_t);
	void handle_association_change_event(struct sctp_assoc_change*);
	void handle_remote_error_event(struct sctp_remote_error*);
	void handle_stream_change_event(struct sctp_stream_change_event*);
	void handle_stream_reset_event(struct sctp_stream_reset_event*);
	void handle_shutdown_event(struct sctp_shutdown_event*);
	void handle_adaptation_indication(struct sctp_adaptation_event*);
	void handle_send_failed_event(struct sctp_send_failed_event*);
	void handle_peer_address_change_event(struct sctp_paddr_change*);
	void handle_sender_dry_event(struct sctp_sender_dry_event*);

	void state(Client::State);
};

} //namespace sctp

std::ostream& operator<<(std::ostream&, const sctp::Client::Config&);

#endif // __sctp_client_impl_hpp__