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


constexpr uint16_t DEFAULT_LOCAL_UDP_ENCAPS_PORT = 9898;

constexpr const char* DEFAULT_SERVER_ADDRESS = "127.0.0.1";
constexpr uint16_t DEFAULT_SERVER_UDP_ENCAPS_PORT = 9899;
constexpr uint16_t DEFAULT_SERVER_SCTP_PORT = 5001;



class SCTPClient {
public:
   enum LogLevel {
   	TRACE,
      DEBUG,
      INFO,
      WARNING,
      ERROR,
		CRITICAL
   };

   enum State {
   	NONE,
      SCTP_CONNECTING,
      SCTP_CONNECTED,
      SSL_HANDSHAKING,
      SSL_CONNECTED,
		SSL_SHUTDOWN,
		PURGE
   };

	using SCTPClient_data_cback_t = std::function<void(const std::string&)>;
	using SCTPClient_state_cback_t = std::function<void(State)>;
	using SCTPServer_debug_t = std::function<void(SCTPClient::LogLevel, const std::string&)>;	

	struct Config {
		Config() = default;
		virtual ~Config() = default;
		Config(const Config& oth) = delete;
		Config& operator=(const Config& oth) = delete;

		uint16_t udp_encaps_port { DEFAULT_LOCAL_UDP_ENCAPS_PORT };
		uint16_t server_udp_port { DEFAULT_SERVER_UDP_ENCAPS_PORT };
		uint16_t server_sctp_port { DEFAULT_SERVER_SCTP_PORT };
		std::string server_address { DEFAULT_SERVER_ADDRESS };

		std::string cert_filename { "../certs/client-cert.pem" };
		std::string key_filename { "../certs/client-key.pem" };

		SCTPClient_data_cback_t data_cback_f = nullptr;
		SCTPServer_debug_t debug_f = nullptr;
		SCTPClient_state_cback_t state_f = nullptr;
	};

	SCTPClient();

	SCTPClient(std::shared_ptr<SCTPClient::Config> p);

	SCTPClient(const SCTPClient& oth) = delete;

	SCTPClient& operator=(const SCTPClient& oth) = delete;

	/* sync */
	void init();

	/* async */
	void run();

	bool connected() const { return state == SSL_CONNECTED; };

	ssize_t sctp_send(const std::string&);

	ssize_t sctp_send(const void* buf, size_t len);

	void stop();

	virtual ~SCTPClient();

	friend std::ostream& operator<<(std::ostream&, const SCTPClient&);

	std::shared_ptr<Config> cfg_;

private:

	SSL_h ssl_obj { SSL_h::CLIENT };

	SSL* ssl = nullptr;
	BIO* output_bio = nullptr;
	BIO* input_bio = nullptr;

	State state = NONE;

	int udp_sock_fd;

	struct socket* sock = nullptr;

	std::atomic_bool isConnected { false };

	std::thread udp_thr;

	void init_local_UDP();
	void init_remote_UDP();
	void init_SCTP();
	
	ssize_t sctp_send_raw(const void* buf, size_t len);

	static int conn_output(void* obj, void *buf, size_t length, uint8_t tos, uint8_t set_df);
	static void handle_upcall(struct socket* sock, void* arg, int flgs);

	void handle_server_data(void* buffer, ssize_t n, const struct sockaddr_in& addr,
		const struct sctp_recvv_rn& rcv_info, unsigned int infotype, int flags);

	void handle_notification(union sctp_notification* notif, size_t n);
	void handle_association_change_event(struct sctp_assoc_change* sac);
	void handle_remote_error_event(struct sctp_remote_error* sre);
	void handle_stream_change_event(struct sctp_stream_change_event* strchg);
	void handle_stream_reset_event(struct sctp_stream_reset_event* strrst);
	void handle_shutdown_event(struct sctp_shutdown_event*);
	void handle_adaptation_indication(struct sctp_adaptation_event* sai);
	void handle_send_failed_event(struct sctp_send_failed_event* ssfe);
	void handle_peer_address_change_event(struct sctp_paddr_change* spc);


	void set_state(SCTPClient::State new_state);

	void udp_loop();
};


std::ostream& operator<<(std::ostream& out, const SCTPClient::Config& c);