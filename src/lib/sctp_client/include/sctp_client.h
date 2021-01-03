#pragma once

#include <thread>
#include <functional>
#include <string>
#include <atomic>
#include <unordered_map>
#include <vector>
#include <cstring>

#include <arpa/inet.h>

#include <openssl/ssl.h>


constexpr uint16_t DEFAULT_LOCAL_UDP_ENCAPS_PORT = 0; //choose ephemeral
constexpr uint16_t DEFAULT_LOCAL_SCTP_PORT = 0; // set the same as udp encaps port

constexpr const char* DEFAULT_SERVER_ADDRESS = "127.0.0.1";
constexpr uint16_t DEFAULT_SERVER_UDP_ENCAPS_PORT = 9899;
constexpr uint16_t DEFAULT_SERVER_SCTP_PORT = 5001;

constexpr const char* DEFAULT_CLIENT_CERT_FILENAME = "client-cert.pem";
constexpr const char* DEFAULT_CLIENT_KEY_FILENAME = "client-key.pem";


class SSL_h;
template <typename T>
class SyncQueue;


namespace sctp
{

struct Data;
constexpr auto DEFAULT_SCTP_MESSAGE_SIZE_BYTES = 1 << 16;


enum class LogLevel
{
	TRACE,
	DEBUG,
	INFO,
	WARNING,
	ERROR,
	CRITICAL
};


class Client
{
public:
	enum class State
	{
		NONE,
		INITIALIZED,
		SCTP_CONNECTING,
		SCTP_CONNECTED,
		SSL_HANDSHAKING,
		SSL_CONNECTED,
		SSL_SHUTDOWN,
		PURGE
   };

	using Client_cback_t = std::function<void(std::unique_ptr<std::vector<char>>)>;
	using Client_state_cback_t = std::function<void(State)>;
	using Client_debug_t = std::function<void(sctp::LogLevel, const std::string&)>;	
	using Client_send_possible_t = std::function<void()>;

	struct Config
	{
		Config() = default;
		Config(const Config&) = delete;
		Config& operator=(const Config&) = delete;
		virtual ~Config() = default;

		uint16_t udp_encaps_port {DEFAULT_LOCAL_UDP_ENCAPS_PORT};
		uint16_t sctp_port {DEFAULT_LOCAL_SCTP_PORT};
		uint16_t server_udp_port {DEFAULT_SERVER_UDP_ENCAPS_PORT};
		uint16_t server_sctp_port {DEFAULT_SERVER_SCTP_PORT};
		std::string server_address {DEFAULT_SERVER_ADDRESS};

		size_t message_size {sctp::DEFAULT_SCTP_MESSAGE_SIZE_BYTES};

		std::string cert_filename {DEFAULT_CLIENT_CERT_FILENAME};
		std::string key_filename {DEFAULT_CLIENT_KEY_FILENAME};

		Client_cback_t data_cback_f {nullptr};
		Client_debug_t debug_cback_f {nullptr};
		Client_state_cback_t state_cback_f {nullptr};
		Client_send_possible_t send_possible_cback_f {nullptr};
	};

	Client();
	explicit Client(std::shared_ptr<Client::Config>);
	Client(const Client&) = delete;
	Client& operator=(const Client&) = delete;
	virtual ~Client();

	/*
		Getter for cfg object
	*/
	std::shared_ptr<Client::Config> cfg() { return cfg_; };

	/* 
		Calling is mandatory. (sync)
	*/
	void init();

	/* 
		Starts client. Doesn't block.
	*/
	void operator()();

	bool connected() const { return state_ == State::SSL_CONNECTED; };

	ssize_t send(const void*, size_t);

	void stop();

	std::string to_string() const;

	friend std::ostream& operator<<(std::ostream&, const sctp::Client&);


private:
	std::shared_ptr<Client::Config> cfg_;

	std::unique_ptr<SSL_h> ssl_obj_ {nullptr};
	SSL* ssl_ {nullptr};
	BIO* output_bio_ {nullptr};
	BIO* input_bio_ {nullptr};

	std::atomic_bool usrsctp_lib_initialized_ {false};
	static inline std::atomic_size_t number_of_instances_ {};

	std::atomic_bool sender_dry_ {false};

	State state_ = State::NONE;

	int udp_sock_fd_ {-1};
	uint16_t bound_udp_encaps_port_ {};
	struct socket* sock_ {nullptr};

	std::unique_ptr<SyncQueue<std::unique_ptr<std::vector<char>>>> raw_udp_data_ {nullptr};
	std::vector<char> sctp_msg_buff_;
	std::vector<char> decrypted_msg_buff_;
	std::vector<char> encrypted_msg_buff_;

	std::thread udp_recv_thr_;
	void udp_recv_loop();

	std::thread udp_data_thr_;
	void handle_raw_udp_data_loop();

	void init_local_UDP();
	void init_remote_UDP();
	void init_usrsctp_lib();		
	void init_SCTP();	
	
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
