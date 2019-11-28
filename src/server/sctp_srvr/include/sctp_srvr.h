#pragma once

#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>

#include "ssl_h.h"
#include "sctp_srvr_client.h"

class SCTPServer;

constexpr uint16_t DEFAULT_UDP_ENCAPS_PORT = 9899;
constexpr uint16_t DEFAULT_SCTP_PORT = 5001;



class SCTPServer {
public:

   enum LogLevel {
   	TRACE,
      DEBUG,
      INFO,
      WARNING,
      ERROR,
		CRITICAL
   };

	using SCTPServer_cback_t = std::function<void(const std::shared_ptr<IClient>, const std::string&)>;
	using SCTPServer_debug_t = std::function<void(SCTPServer::LogLevel, const std::string&)>;	
	using SCTPServer_client_factory_t = 
		std::function<std::shared_ptr<IClient>(struct socket*, SCTPServer&)>;

	struct Config {
		Config() = default;
		virtual ~Config() = default;
		Config(const Config& oth) = delete;
		
		uint16_t udp_encaps_port { DEFAULT_UDP_ENCAPS_PORT };
		uint16_t sctp_port { DEFAULT_SCTP_PORT };

		std::string cert_filename { "../certs/server-cert.pem" };
		std::string key_filename { "../certs/server-key.pem" };
		SCTPServer_cback_t data_cback_f { nullptr };
		SCTPServer_debug_t debug_f { nullptr };
		SCTPServer_client_factory_t client_factory { nullptr };

    	friend std::ostream& operator<<(std::ostream &out, const Config &c); 
	};


	SCTPServer();

	SCTPServer(std::shared_ptr<SCTPServer::Config> p);

	SCTPServer(const SCTPServer& oth) = delete;

	SCTPServer& operator=(const SCTPServer& oth) = delete;

	/*
		usrsctp lib, SSL etc initializations
	*/
	void init();

 	/*
 		Async, runs accept in separate thread
	*/
	void run();

	void send(std::shared_ptr<IClient>& c, const void* data, size_t len);

	/*
		Convenience wrapper
	*/
	void send(std::shared_ptr<IClient>& c, const std::string& message);

	void broadcast(const void* data, size_t len);

	/*
		Convenience wrapper. Sends message to all clients.
	*/
	void broadcast(const std::string& message);


	// might not be called explicitly
	// as dtor also handles correct cleanup
	void stop();
	
	virtual ~SCTPServer();


	/* 
		static object may be used for embedding to dyn library
		(FreeSWITCH module in particular) for RAII on dlopen/dlclose
		(for future use mainly)
 	*/
	static std::shared_ptr<SCTPServer> s_;

	std::shared_ptr<Config> cfg_;

 	friend std::ostream& operator<<(std::ostream &out, const SCTPServer &s);

	friend class Client;
	friend class IClient;;

private:

	void accept_loop();

	void handle_client_data(std::shared_ptr<IClient>& c, const void* buffer, ssize_t n,
		 const struct sockaddr_in& addr, const struct sctp_recvv_rn& rcv_info, unsigned int infotype, int flags);

	static void handle_upcall(struct socket* sock, void* arg, [[maybe_unused]] int flgs);

	void cleanup();

	ssize_t send_raw(std::shared_ptr<IClient>& c, const void* buf, size_t len);

	void drop_client(std::shared_ptr<IClient>&);

	//holds main SSL context etc
	SSL_h ssl_obj_ { SSL_h::SERVER };

	std::thread accept_thr_;
	struct socket* server_sock_;

	std::mutex clients_mutex_;
	std::vector<std::shared_ptr<IClient>> clients_;

};




