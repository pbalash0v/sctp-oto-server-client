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
#include <iclient.h> //socklen_t
#include <server_event.h> //socklen_t


class Client;

namespace sctp
{
enum class LogLevel;
class SSL_h;


constexpr std::uint16_t DEFAULT_UDP_ENCAPS_PORT {9899};
constexpr std::uint16_t DEFAULT_SCTP_PORT {5001};

constexpr std::size_t DEFAULT_SCTP_MESSAGE_SIZE_BYTES {(1 << 16)};

class Server
{
public:
	using event_cback_t = std::function<void(std::unique_ptr<Event>)>;
	using debug_cback_t = std::function<void(sctp::LogLevel, const std::string&)>;	

	struct Config
	{
		uint16_t udp_encaps_port {DEFAULT_UDP_ENCAPS_PORT};
		uint16_t sctp_port {DEFAULT_SCTP_PORT};
		size_t message_size {DEFAULT_SCTP_MESSAGE_SIZE_BYTES};

		std::string cert_filename;
		std::string key_filename;
		
		event_cback_t event_cback_f {nullptr};
		debug_cback_t debug_cback_f {nullptr};

    	friend std::ostream& operator<<(std::ostream &out, const Config &c); 
	};

	explicit Server(std::shared_ptr<Server::Config>);
	
	Server(const Server&) = delete;
	Server& operator=(const Server&) = delete;
	Server(Server&&) = delete;
	Server& operator=(Server&&) = delete;

	virtual ~Server();

	/*
		Getter for cfg object
	*/
	std::shared_ptr<Server::Config> cfg() { return cfg_; };

 	/*
 		Actually starts server.
 		Accepts on server socket in separate thread. (asynchronous).
	*/
	void operator()();

	/*
		Sends message to client.
	*/
	void send(std::shared_ptr<IClient>, const void*, size_t);

	/* 
		might not be called explicitly
		as dtor also handles correct cleanup
	*/
	void stop();
	

 	friend std::ostream& operator<<(std::ostream&, const Server&);

	friend class ::Client;
	friend class ::IClient;

protected:
	std::shared_ptr<IClient> client_factory(struct socket*);

private:
	std::shared_ptr<Server::Config> cfg_;

	std::atomic_bool initialized_ {false};
	/* bad signleton-like implementation */
	inline static std::atomic_bool instance_exists_  {false};

	/* holds main SSL context etc */
	std::unique_ptr<SSL_h> ssl_obj_;

	struct socket* serv_sock_ {nullptr};

	std::thread sctp_msg_handler_;

	std::mutex clients_mutex_;
	std::vector<std::shared_ptr<IClient>> clients_;

private:	
	/*
		Usrsctp lib, SSL etc initializations. (synchronous).
		Calling is mandatory.
	*/
	void init();
	void sctp_msg_handler_loop();
	void try_init_local_UDP();
	static void handle_server_upcall(struct socket*, void* arg, int flgs);
	static void handle_client_upcall(struct socket*, void* arg, int flgs);
	std::shared_ptr<IClient> get_client(const struct socket*);
	void cleanup();
	void drop_client(std::shared_ptr<IClient>);
};

} // namespace sctp

#endif // __sctp_server_h__
