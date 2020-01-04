#pragma once

#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

#include <sys/socket.h> //socklen_t

#include "sync_queue.hpp"
#include "ssl_h.h"
#include "client.h"
#include "client_data.h"
#include "server_event.h"



#ifdef TEST_BUILD
#define MAYBE_VIRTUAL virtual
#else
#define MAYBE_VIRTUAL
#endif


#ifndef NDEBUG
#define log(level, text) do { \
						if (nullptr == cfg_->debug_f) break; \
						std::string s = std::string(); \
						s += std::string(basename(__FILE__)) + \
						 + ", " + std::string(__func__) + \
						 + ":" + std::to_string(__LINE__) + \
						 + "\t " + std::string(text); \
							cfg_->debug_f(level, s); \
						} while (0)
#else
#define log(level, text) do {} while (0)
#endif

#define TRACE(text) log(SCTPServer::TRACE, text)
#define DEBUG(text) log(SCTPServer::DEBUG, text)
#define INFO(text) log(SCTPServer::INFO, text)
#define WARNING(text) log(SCTPServer::WARNING, text)
#define ERROR(text) log(SCTPServer::ERROR, text)
#define CRITICAL(text) log(SCTPServer::CRITICAL, text)

#define TRACE_func_entry() TRACE("Entered " + std::string(__func__))
#define TRACE_func_left() TRACE("Left " + std::string(__func__))



constexpr uint16_t DEFAULT_UDP_ENCAPS_PORT = 9899;
constexpr uint16_t DEFAULT_SCTP_PORT = 5001;

constexpr auto DEFAULT_SCTP_MESSAGE_SIZE_BYTES = (1 << 16);

constexpr const char* DEFAULT_SERVER_CERT_FILENAME = "../certs/server-cert.pem";
constexpr const char* DEFAULT_SERVER_KEY_FILENAME = "../certs/server-key.pem";

class SCTPServer
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


	using SCTPServer_event_cback_t = std::function<void(std::unique_ptr<Event>)>;
	using SCTPServer_debug_t = std::function<void(SCTPServer::LogLevel, const std::string&)>;	

	struct Config
	{
		Config() = default;
		virtual ~Config() = default;
		Config(const Config& oth) = delete;
		Config& operator=(const Config& oth) = delete;

		uint16_t udp_encaps_port { DEFAULT_UDP_ENCAPS_PORT };
		uint16_t sctp_port { DEFAULT_SCTP_PORT };
		size_t message_size { DEFAULT_SCTP_MESSAGE_SIZE_BYTES };

		std::string cert_filename { DEFAULT_SERVER_CERT_FILENAME };
		std::string key_filename { DEFAULT_SERVER_KEY_FILENAME };
		SCTPServer_event_cback_t event_cback_f { nullptr };
		SCTPServer_debug_t debug_f { nullptr };

    	friend std::ostream& operator<<(std::ostream &out, const Config &c); 
	};

	SCTPServer();
	SCTPServer(std::shared_ptr<SCTPServer::Config> p);
	SCTPServer(const SCTPServer& oth) = delete;
	SCTPServer& operator=(const SCTPServer& oth) = delete;
	virtual ~SCTPServer();

	/*
		Getter for cfg object
	*/
	std::shared_ptr<SCTPServer::Config> cfg() { return cfg_; };

	/*
		Usrsctp lib, SSL etc initializations. (synchronous).
		Calling is mandatory.
	*/
	void init();

 	/*
 		Actually starts server.
 		Accepts on server socket in separate thread. (asynchronous).
	*/
	void operator()();

	/*
		Sends message to client.
	*/
	void send(std::shared_ptr<IClient>&, const void*, size_t);

	/*
		Sends message to all clients.
	*/
	void broadcast(const void*, size_t);

	/* 
		might not be called explicitly
		as dtor also handles correct cleanup
	*/
	void stop();
	

 	friend std::ostream& operator<<(std::ostream&, const SCTPServer&);

	friend class Client;
	friend class IClient;
protected:

	MAYBE_VIRTUAL std::shared_ptr<IClient> client_factory(struct socket*);

	/* 
		MAYBE_VIRTUAL is a macro, which expands to virtual keyword on test builds.
		Such function declarations used for unit testing as a "seam" point.
		In real code scope-resolved to calls of usrsctp lib functions.
	 */
	MAYBE_VIRTUAL struct socket* usrsctp_socket(int domain, int type, int protocol,
               int (*receive_cb)(struct socket* sock, union sctp_sockstore addr, void* data,
                                 size_t datalen, struct sctp_rcvinfo, int flags, void* ulp_info),
               int (*send_cb)(struct socket*, uint32_t),
               uint32_t, void*);
	MAYBE_VIRTUAL int usrsctp_bind(struct socket*, struct sockaddr*, socklen_t);
	MAYBE_VIRTUAL int usrsctp_listen(struct socket*, int);
	MAYBE_VIRTUAL struct socket* usrsctp_accept(struct socket*, struct sockaddr*, socklen_t*);

private:
	std::shared_ptr<SCTPServer::Config> cfg_;

	std::atomic_bool initialized_ { false };
	static std::atomic_bool instance_exists_;

	/* holds main SSL context etc */
	SSL_h ssl_obj_ { SSL_h::SERVER };

	struct socket* serv_sock_ { nullptr };

	std::thread sctp_msg_handler_;
	void sctp_msg_handler_loop();

	std::mutex clients_mutex_;
	std::vector<std::shared_ptr<IClient>> clients_;

	void try_init_local_UDP();

	static void handle_server_upcall(struct socket* sock, void* arg, int flgs);
	static void handle_client_upcall(struct socket* sock, void* arg, int flgs);

	void client_state(std::shared_ptr<IClient>&, IClient::State);
	std::shared_ptr<IClient> get_client(const struct socket* sock);

	void handle_notification(std::shared_ptr<IClient>&, union sctp_notification*, size_t);
	void handle_client_data(std::shared_ptr<IClient>& c, const void* buffer, size_t n,
		 const struct sockaddr_in& addr, const struct sctp_recvv_rn& rcv_info, unsigned int infotype);

	void handle_association_change_event(std::shared_ptr<IClient>&, struct sctp_assoc_change*);

	void cleanup();

	ssize_t send_raw(std::shared_ptr<IClient>&, const void*, size_t);

	void drop_client(std::shared_ptr<IClient>&);
};




