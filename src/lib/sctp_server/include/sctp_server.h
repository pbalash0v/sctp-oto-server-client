#ifndef __sctp_server_h__
#define __sctp_server_h__

#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

#include <sys/socket.h> //socklen_t

#include "client.h"
#include "server_event.h"


#ifdef TEST_BUILD
#define MAYBE_VIRTUAL virtual
#else
#define MAYBE_VIRTUAL
#endif


constexpr uint16_t DEFAULT_UDP_ENCAPS_PORT {9899};
constexpr uint16_t DEFAULT_SCTP_PORT {5001};

constexpr auto DEFAULT_SCTP_MESSAGE_SIZE_BYTES {(1 << 16)};

constexpr auto DEFAULT_SERVER_CERT_FILENAME {"server-cert.pem"};
constexpr auto DEFAULT_SERVER_KEY_FILENAME {"server-key.pem"};

namespace sctp
{
	enum class LogLevel;
}

class SSL_h;

class SCTPServer
{
public:
	using SCTPServer_event_cback_t = std::function<void(std::unique_ptr<Event>)>;
	using SCTPServer_debug_t = std::function<void(sctp::LogLevel, const std::string&)>;	

	struct Config
	{
		uint16_t udp_encaps_port {DEFAULT_UDP_ENCAPS_PORT};
		uint16_t sctp_port {DEFAULT_SCTP_PORT};
		size_t message_size {DEFAULT_SCTP_MESSAGE_SIZE_BYTES};

		std::string cert_filename {DEFAULT_SERVER_CERT_FILENAME};
		std::string key_filename {DEFAULT_SERVER_KEY_FILENAME};
		
		SCTPServer_event_cback_t event_cback_f {nullptr};
		SCTPServer_debug_t debug_cback_f {nullptr};

    	friend std::ostream& operator<<(std::ostream &out, const Config &c); 
	};

	SCTPServer();
	SCTPServer(std::shared_ptr<SCTPServer::Config>);
	
	SCTPServer(const SCTPServer&) = delete;
	SCTPServer& operator=(const SCTPServer&) = delete;

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
               int (*send_cb)(struct socket*, uint32_t, void* ulp_info),
               uint32_t, void*);
	MAYBE_VIRTUAL int usrsctp_bind(struct socket*, struct sockaddr*, socklen_t);
	MAYBE_VIRTUAL int usrsctp_listen(struct socket*, int);
	MAYBE_VIRTUAL struct socket* usrsctp_accept(struct socket*, struct sockaddr*, socklen_t*);

private:
	std::shared_ptr<SCTPServer::Config> cfg_;

	std::atomic_bool initialized_ {false};
	static std::atomic_bool instance_exists_;

	/* holds main SSL context etc */
	std::unique_ptr<SSL_h> ssl_obj_;

	struct socket* serv_sock_ {nullptr};

	std::thread sctp_msg_handler_;

	std::mutex clients_mutex_;
	std::vector<std::shared_ptr<IClient>> clients_;

	void sctp_msg_handler_loop();

	void try_init_local_UDP();

	static void handle_server_upcall(struct socket*, void* arg, int flgs);
	static void handle_client_upcall(struct socket*, void* arg, int flgs);

	std::shared_ptr<IClient> get_client(const struct socket*);

	void cleanup();

	void drop_client(std::shared_ptr<IClient>&);
};



#endif // __sctp_server_h__
