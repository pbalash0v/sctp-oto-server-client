#ifndef __sctp_server_impl_hpp__
#define __sctp_server_impl_hpp__

#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

#include <sys/socket.h> //socklen_t

#include <sctp_server.hpp>
#include <log_level.hpp>
#include <iclient.hpp>


class Client;

namespace sctp
{
enum class LogLevel;
class SSLWrapper;


constexpr std::uint16_t DEFAULT_UDP_ENCAPS_PORT {9899};
constexpr std::uint16_t DEFAULT_SCTP_PORT {5001};

constexpr std::size_t DEFAULT_SCTP_MESSAGE_SIZE_BYTES {(1 << 16)};

class ServerImpl final
{
public:
	explicit ServerImpl(std::shared_ptr<Server::Config>);
	
	ServerImpl(const ServerImpl&) = delete;
	ServerImpl& operator=(const ServerImpl&) = delete;
	ServerImpl(ServerImpl&&) = delete;
	ServerImpl& operator=(ServerImpl&&) = delete;

	~ServerImpl();

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
	

 	friend std::ostream& operator<<(std::ostream&, const ServerImpl&);

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
	std::unique_ptr<SSLWrapper> ssl_obj_;

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

#endif // __sctp_server_impl_hpp__
