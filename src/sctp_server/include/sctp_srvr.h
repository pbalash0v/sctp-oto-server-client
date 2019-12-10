#pragma once

#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

#include "ssl_h.h"
#include "sctp_srvr_client.h"


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

	using SCTPServer_cback_t = std::function<void(const std::shared_ptr<IClient>, std::shared_ptr<IClient::Data>)>;
	using SCTPServer_debug_t = std::function<void(SCTPServer::LogLevel, const std::string&)>;	
	using SCTPServer_client_factory_t = 
		std::function<std::shared_ptr<IClient>(struct socket*, SCTPServer&)>;

	class Config
	{
	public:
		Config() = default;
		virtual ~Config() = default;
		Config(const Config& oth) = delete;
		
		uint16_t udp_encaps_port { DEFAULT_UDP_ENCAPS_PORT };
		uint16_t sctp_port { DEFAULT_SCTP_PORT };

		std::string cert_filename { "../certs/server-cert.pem" };
		std::string key_filename { "../certs/server-key.pem" };
		SCTPServer_cback_t data_cback_f { nullptr };
		SCTPServer_debug_t debug_f { nullptr };
		
		friend class SCTPServer;
    	friend std::ostream& operator<<(std::ostream &out, const Config &c); 

	};


	static SCTPServer& get_instance() {
		static SCTPServer s_;
		return s_;
	}

	SCTPServer(const SCTPServer& oth) = delete;

	SCTPServer& operator=(const SCTPServer& oth) = delete;

	/*
		Usrsctp lib, SSL etc initializations. (synchronous).
		Mandatory
	*/
	void init();

 	/*
 		Accepts on server socket in separate thread. (asynchronous).
	*/
	void run();

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
	

	virtual ~SCTPServer();




	std::shared_ptr<Config> cfg_;

 	friend std::ostream& operator<<(std::ostream&, const SCTPServer&);

	friend class Client;
	friend class IClient;

protected:

	SCTPServer();

	SCTPServer(std::shared_ptr<SCTPServer::Config> p);

	MAYBE_VIRTUAL std::shared_ptr<IClient> client_factory(struct socket*);

	/* 
		MAYBE_VIRTUAL is a macro, which expands to virtual keyword on test builds.
		Such function declarations used for unit testing as a "seam" point.
		In real code scope-resolved to calls of usrsctp lib functions.
	 */
	MAYBE_VIRTUAL struct socket* usrsctp_socket(int domain, int type, int protocol,
               int (*receive_cb)(struct socket *sock, union sctp_sockstore addr, void *data,
                                 size_t datalen, struct sctp_rcvinfo, int flags, void *ulp_info),
               int (*send_cb)(struct socket *sock, uint32_t sb_free),
               uint32_t sb_threshold,
               void *ulp_info);
	MAYBE_VIRTUAL int usrsctp_bind(struct socket*, struct sockaddr*, socklen_t);
	MAYBE_VIRTUAL int usrsctp_listen(struct socket*, int);
	MAYBE_VIRTUAL struct socket* usrsctp_accept(struct socket*, struct sockaddr*, socklen_t*);

private:

	void try_init_local_UDP();

	void handle_notification(std::shared_ptr<IClient>&, union sctp_notification*, size_t);

	void handle_client_data(std::shared_ptr<IClient>& c, const void* buffer, ssize_t n,
		 const struct sockaddr_in& addr, const struct sctp_recvv_rn& rcv_info, unsigned int infotype, int flags);

	static void handle_client_upcall(struct socket* sock, void* arg, int flgs);

	static void handle_server_upcall(struct socket* sock, void* arg, int flgs);

	void cleanup();

	ssize_t send_raw(std::shared_ptr<IClient>&, const void*, size_t);

	void drop_client(std::shared_ptr<IClient>&);


	std::atomic_bool initialized { false };

	/* holds main SSL context etc */
	SSL_h ssl_obj_ { SSL_h::SERVER };

	struct socket* serv_sock_ { nullptr };

	std::mutex clients_mutex_;
	std::vector<std::shared_ptr<IClient>> clients_;
};



