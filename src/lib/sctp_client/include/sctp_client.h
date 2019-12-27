#pragma once

#include <thread>
#include <functional>
#include <string>
#include <atomic>
#include <unordered_map>
#include <vector>
#include <cstring>

#include <arpa/inet.h>

#include "ssl_h.h"


constexpr uint16_t DEFAULT_LOCAL_UDP_ENCAPS_PORT = 0; //choose ephemeral
constexpr uint16_t DEFAULT_LOCAL_SCTP_PORT = 0; // set the same as udp encaps port

constexpr const char* DEFAULT_SERVER_ADDRESS = "127.0.0.1";
constexpr uint16_t DEFAULT_SERVER_UDP_ENCAPS_PORT = 9899;
constexpr uint16_t DEFAULT_SERVER_SCTP_PORT = 5001;

namespace sctp {
	constexpr auto DEFAULT_SCTP_MESSAGE_SIZE_BYTES = 1 << 16;
}

constexpr const char* DEFAULT_CLIENT_CERT_FILENAME = "../certs/client-cert.pem";
constexpr const char* DEFAULT_CLIENT_KEY_FILENAME = "../certs/client-key.pem";


class SCTPClient
{
public:
   enum LogLevel
   {
   	TRACE,
      DEBUG,
      INFO,
      WARNING,
      ERROR,
		CRITICAL
   };

   enum State
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

   struct Data {
   	Data();
   	explicit Data(const void*, size_t);
		Data(const Data& oth) = delete;
		Data& operator=(const Data& oth) = delete;
		Data(Data&& other);
		virtual ~Data();

		Data& operator=(Data&& other);

   	size_t size { 0 };
   	void* buf { nullptr };
	};

	using SCTPClient_cback_t = std::function<void(std::unique_ptr<SCTPClient::Data>)>;
	using SCTPClient_state_cback_t = std::function<void(State)>;
	using SCTPClient_debug_t = std::function<void(SCTPClient::LogLevel, const std::string&)>;	

	struct Config
	{
		Config() = default;
		Config(const Config&) = delete;
		Config& operator=(const Config&) = delete;
		virtual ~Config() = default;

		uint16_t udp_encaps_port { DEFAULT_LOCAL_UDP_ENCAPS_PORT };
		uint16_t sctp_port { DEFAULT_LOCAL_SCTP_PORT };
		uint16_t server_udp_port { DEFAULT_SERVER_UDP_ENCAPS_PORT };
		uint16_t server_sctp_port { DEFAULT_SERVER_SCTP_PORT };
		std::string server_address { DEFAULT_SERVER_ADDRESS };

		size_t message_size { sctp::DEFAULT_SCTP_MESSAGE_SIZE_BYTES };

		std::string cert_filename { DEFAULT_CLIENT_CERT_FILENAME };
		std::string key_filename { DEFAULT_CLIENT_KEY_FILENAME };

		SCTPClient_cback_t data_cback_f = nullptr;
		SCTPClient_debug_t debug_cback_f = nullptr;
		SCTPClient_state_cback_t state_cback_f = nullptr;
	};

	SCTPClient();
	explicit SCTPClient(std::shared_ptr<SCTPClient::Config>);
	SCTPClient(const SCTPClient&) = delete;
	SCTPClient& operator=(const SCTPClient&) = delete;
	virtual ~SCTPClient();

	/*
		Getter for cfg object
	*/
	std::shared_ptr<SCTPClient::Config> cfg() { return cfg_; };

	/* 
		Calling is mandatory. (sync)
	*/
	void init();

	/* 
		Starts client. Doesn't block.
	*/
	void operator()();

	bool connected() const { return state_ == SSL_CONNECTED; };

	ssize_t send(const void*, size_t);

	void stop();

	std::string to_string() const;

	friend std::ostream& operator<<(std::ostream&, const SCTPClient&);


private:
	std::shared_ptr<SCTPClient::Config> cfg_;

	SSL_h ssl_obj { SSL_h::CLIENT };
	SSL* ssl { nullptr };
	BIO* output_bio { nullptr };
	BIO* input_bio { nullptr };

	std::atomic_bool usrsctp_lib_initialized { false };
	static std::atomic_size_t number_of_instances;

	std::atomic_bool sender_dry { false };

	State state_ = NONE;

	int udp_sock_fd;
	uint16_t bound_udp_encaps_port_ { 0 };
	struct socket* sock { nullptr };

	std::vector<char> sctp_msg_buff_;
	std::vector<char> decrypted_msg_buff_;
	std::vector<char> encrypted_msg_buff_;

	std::thread udp_thr;
	void udp_loop();

	void init_local_UDP();
	void init_remote_UDP();
	void init_usrsctp_lib();		
	void init_SCTP();	
	
	ssize_t send_raw_(const void*, size_t);

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

	void state(SCTPClient::State);
};


std::ostream& operator<<(std::ostream&, const SCTPClient::Config&);		
