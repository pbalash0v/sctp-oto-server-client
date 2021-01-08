#ifndef __sctp_server_hpp__
#define __sctp_server_hpp__

#include <string>
#include <memory>
#include <functional>

#include <log_level.hpp>
#include <iclient.hpp>


namespace sctp
{
class ServerImpl;


struct ServerEvent
{
	enum class Type
	{
		NONE,
		CLIENT_DATA,
		CLIENT_STATE,
		CLIENT_SEND_POSSIBLE,
		ERROR
	};

	explicit ServerEvent(Type, std::shared_ptr<IClient>);	
	explicit ServerEvent(Type, std::shared_ptr<IClient>, IClient::State);
	explicit ServerEvent(Type, std::shared_ptr<IClient>, std::vector<char>);
	explicit ServerEvent(const sctp::Message&);

	ServerEvent(const ServerEvent&) = delete;
	ServerEvent& operator=(const ServerEvent&) = delete;
	ServerEvent(ServerEvent&&) = default;
	ServerEvent& operator=(ServerEvent&&) = default;

	~ServerEvent() = default;

	Type type {Type::NONE};
	std::shared_ptr<IClient> client {nullptr};
	IClient::State client_state {IClient::State::NONE};
	std::vector<char> client_data;
};


class Server final
{
public:
	using event_cback_t = std::function<void(std::unique_ptr<ServerEvent>)>;
	using debug_cback_t = std::function<void(sctp::LogLevel, const std::string&)>;

	struct Config
	{
		constexpr static std::uint16_t DEFAULT_UDP_ENCAPS_PORT {9899};
		constexpr static std::uint16_t DEFAULT_SCTP_PORT {5001};

		constexpr static std::size_t DEFAULT_SCTP_MESSAGE_SIZE_BYTES {(1 << 16)};

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
	Server(Server&&) = default;
	Server& operator=(Server&&) = default;

	~Server();
	/*
		Getter for cfg object
	*/
	std::shared_ptr<Server::Config> cfg();

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

private:
	std::unique_ptr<sctp::ServerImpl> server_impl_ptr_{nullptr};

};

} // namespace sctp

#endif // __sctp_server_h__
