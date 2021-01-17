#ifndef __sctp_client_hpp__
#define __sctp_client_hpp__

#include <memory>
#include <functional>
#include <string>
#include <vector>

#include <log_level.hpp>


namespace sctp
{
class ClientImpl;

class Client final
{
public:
	static constexpr const uint16_t DEFAULT_LOCAL_UDP_ENCAPS_PORT = 0; //choose ephemeral
	static constexpr const uint16_t DEFAULT_LOCAL_SCTP_PORT = 0; // set the same as udp encaps port

	static constexpr const char* DEFAULT_SERVER_ADDRESS = "127.0.0.1";
	static constexpr const uint16_t DEFAULT_SERVER_UDP_ENCAPS_PORT = 9899;
	static constexpr const uint16_t DEFAULT_SERVER_SCTP_PORT = 5001;

	static constexpr const auto DEFAULT_SCTP_MESSAGE_SIZE_BYTES {1 << 16};

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
		uint16_t udp_encaps_port {DEFAULT_LOCAL_UDP_ENCAPS_PORT};
		uint16_t sctp_port {DEFAULT_LOCAL_SCTP_PORT};
		uint16_t server_udp_port {DEFAULT_SERVER_UDP_ENCAPS_PORT};
		uint16_t server_sctp_port {DEFAULT_SERVER_SCTP_PORT};
		std::string server_address {DEFAULT_SERVER_ADDRESS};

		size_t message_size {DEFAULT_SCTP_MESSAGE_SIZE_BYTES};

		std::string cert_filename {};
		std::string key_filename {};

		Client_cback_t data_cback_f {nullptr};
		Client_debug_t debug_cback_f {nullptr};
		Client_state_cback_t state_cback_f {nullptr};
		Client_send_possible_t send_possible_cback_f {nullptr};

		friend std::ostream& operator<<(std::ostream&, const Config&);
	};

	explicit Client(std::shared_ptr<Client::Config>);
	Client(const Client&) = delete;
	Client& operator=(const Client&) = delete;
	Client(Client&&) = default;
	Client& operator=(Client&&) = default;	
	~Client();

	/*
		Getter for cfg object
	*/
	std::shared_ptr<Client::Config> cfg();
	const std::shared_ptr<Client::Config> cfg() const;

	/* 
		Starts client. Doesn't block.
	*/
	void operator()();

	bool connected() const noexcept;

	ssize_t send(const void*, size_t);

	void stop();

	std::string to_string() const;

	friend std::ostream& operator<<(std::ostream&, const Client&);

private:
	std::unique_ptr<ClientImpl> client_impl_ptr_ {nullptr};
};


} //namespace sctp


#endif // __sctp_client_h__