#include <iostream>
#include <cstring>
#include <string>
#include <chrono>
#include <algorithm>
#include <thread>
#include <sstream>

#include <boost/scope_exit.hpp>
#include <boost/assert.hpp>

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <usrsctp.h>

#include "sync_queue.hpp"
#include "client.hpp"
#include "client_sctp_message.hpp"
#include "log_level.hpp"
#include "logging.hpp"
#include "ssl.hpp"
#include "helper.hpp"
#include "sctp_server_impl.hpp"



namespace
{

SyncQueue<std::unique_ptr<sctp::Message>> sctp_msgs_;

inline void set_thread_name(std::thread& thread, const char* name)
{
   auto handle = thread.native_handle();
   pthread_setname_np(handle, name);
}

inline std::string client_errno(const char* func, const std::shared_ptr<sctp::Server::IClient>& c)
{
	std::ostringstream oss;

	oss << func ;
	oss <<": ";
	oss << c;
	oss << " ";
	oss << strerror(errno);

	return oss.str();
}

} //anon namespace

namespace sctp
{

ServerImpl::ServerImpl(std::shared_ptr<Server::Config> ptr)
	: cfg_{ptr}
	, ssl_obj_{std::make_unique<SSLWrapper>(SSLWrapper::Type::SERVER)}
{
	if (instance_exists_) throw std::logic_error("Singleton !"); // :(
	instance_exists_ = true;
	init();
}

std::shared_ptr<Server::IClient> ServerImpl::client_factory(struct socket* s)
{
	std::shared_ptr<Server::IClient> client{};

	try
	{
		client = std::make_shared<Client>(s, *this, cfg_->message_size);
	}
	catch (const std::runtime_error& exc)
	{
		ERROR(std::string{"Client construction failed: "} + exc.what());
	}

	return client;
};

/*
	From usrsctp lib author's github on calling usrsctp_close() after usrsctp_shutdown(SHUT_RDWR):
	"...only calling usrsctp_close() has the same effect.
	However, you won't be able to receive any notifications,
	since you have closed the socket. This is normal socket API behaviour."
*/
ServerImpl::~ServerImpl()
{
	TRACE_func_entry();
	BOOST_SCOPE_EXIT_ALL(&)
	{
		instance_exists_ = false;
		TRACE_func_left();
	};

	cleanup();

	bool needs_force_close = false;

	TRACE("before first usrsctp_finish loop");
	for (size_t i = 0; i < 3; i++) {
		if (usrsctp_finish() != 0) {
			needs_force_close = true;
			TRACE("waiting to retry usrsctp_finish()...");
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		} else {
			needs_force_close = false;
			break;
		}
	}
	TRACE("after first usrsctp_finish loop");

	if (needs_force_close)
	{
		TRACE("before force close of clients");
		for (auto& c : clients_) {
			try {
				c->state(Server::IClient::State::PURGE);
			} catch (...) {}
		}
		TRACE("force close of clients done");

		TRACE("before final usrsctp_finish loop");
		if (usrsctp_finish() != 0) {
			ERROR(std::string("usrsctp_finish failed: ") + strerror(errno));
		}
		TRACE("before usrsctp_finish loop");
	}

	TRACE("About to join sctp msgs handling thread");
	if (sctp_msg_handler_.joinable())
	{
		//sctp_msgs_.enqueue(std::make_unique<SCTPMessage>());
		sctp_msgs_.enqueue(std::unique_ptr<sctp::Message>{});
		sctp_msg_handler_.join();
	}
	TRACE("sctp msgs handling thread joined");
}

/*
	(1) This closes accepting server socket, which should always succeed immediately (?).
	(2) This also sets SCTP_SRV_INITIATED_SHUTDOWN state for every connected client,
	which leads to SCTP SHUTDOWN being sent to all clients.
	In perfect scenario every connected client replys with SHUTDOWN_ACK
	which leads to notification SCTP_ASSOC_CHANGE SCTP_SHUTDOWN_COMP in a handle_client_upcall
	and finally usrsctp_recvv resulting in 0, where it is removed from clients_ vec.
*/
void ServerImpl::cleanup()
{
	TRACE_func_entry(); BOOST_SCOPE_EXIT_ALL(&) { TRACE_func_left(); };

	{
		std::lock_guard<std::mutex> _ { clients_mutex_ };

		if (serv_sock_) {
			TRACE("before serv_sock_ usrsctp_shutdown");
			usrsctp_shutdown(serv_sock_, SHUT_RDWR);
			TRACE("serv_sock_ usrsctp_shutdown complete");
		}

		if (serv_sock_) {
			TRACE("server socket usrsctp_close");
			usrsctp_close(serv_sock_);
			TRACE("server socket closed");
		}

		/* shutdown and cleanup clients */
		TRACE("before clients shutdown");
		for (auto& c : clients_) {
			try {
				c->state(Server::IClient::State::SCTP_SRV_INITIATED_SHUTDOWN);
			} catch (...) {}
		}
		TRACE("clients shutdown done");
	}
}

/* 
	usrsctp lib allows to call usrsctp_init for two simulteneously running processes
	trying to bind to same udp encaps port without error if port hase already been bound
	(maybe there is some param exists to prevent this that I miss ?)
	This is some kind of hack to try manually creating UDP socket and see if we can do this.
	Will throw runtime_error if udp encaps port already in use.
*/
void ServerImpl::try_init_local_UDP()
{
	TRACE_func_entry(); BOOST_SCOPE_EXIT_ALL(&) { TRACE_func_left(); };

	/* will point to the result */
	struct addrinfo* serv_info {nullptr};
	/* RAII for serv_info */
	std::unique_ptr<struct addrinfo, std::function<void(struct addrinfo*)>> serv_info_ptr
		 (nullptr, [&](auto s) { freeaddrinfo(s); });

	struct addrinfo hints;

	memset(&hints, 0, sizeof hints); // make sure the struct is empty
	hints.ai_family = AF_INET;			// IPV4 only
	hints.ai_socktype = SOCK_DGRAM;  // UDP socket
	hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

	int status;
	if ((status = getaddrinfo(nullptr, std::to_string(cfg_->udp_encaps_port).c_str(),
		 &hints, &serv_info)) != 0) {
		CRITICAL(std::string{"getaddrinfo: "} + gai_strerror(status));
		throw std::runtime_error(gai_strerror(status));
	} else {
		serv_info_ptr.reset(serv_info);
	}

	char ipstr[INET_ADDRSTRLEN];
	for (struct addrinfo* p = serv_info; p; p = p->ai_next) {
      struct sockaddr_in* ipv4 = (struct sockaddr_in *) p->ai_addr;
      void* addr = &(ipv4->sin_addr);
		inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
	}

	int temp_sock_fd;
	if ((temp_sock_fd = socket(serv_info->ai_family, serv_info->ai_socktype, serv_info->ai_protocol)) <= 0) {
		CRITICAL(std::string("socket: ") + strerror(errno));
		throw std::runtime_error(strerror(errno));
	}

	if (bind(temp_sock_fd, serv_info->ai_addr, serv_info->ai_addrlen) < 0) {
		CRITICAL(std::string("bind: ") + strerror(errno));
		throw std::runtime_error(strerror(errno));
	}

	if (close(temp_sock_fd) < 0) {
		CRITICAL(std::string("close: ") + strerror(errno));
		throw std::runtime_error(strerror(errno));
	}
}

void ServerImpl::init()
{
	TRACE_func_entry(); BOOST_SCOPE_EXIT_ALL(&) { TRACE_func_left(); };

	if (initialized_) throw std::logic_error("Server is already initialized.");

	if (auto& c_and_k_ptr = ssl_obj_->init(cfg_->cert_filename, cfg_->key_filename); c_and_k_ptr)
	{
		cfg_->cert_filename = c_and_k_ptr->cert();
		cfg_->key_filename = c_and_k_ptr->key();
	}

	sctp_msg_handler_ = std::thread {&ServerImpl::sctp_msg_handler_loop, this};
	set_thread_name(sctp_msg_handler_, "SCTP msgs");

	try_init_local_UDP();

	usrsctp_init(cfg_->udp_encaps_port,
					/* should udp socket be handled by usrsctp */ NULL,
		 			/* SCTP lib's debug cback */ NULL);

	/*
		Do not send ABORTs in response to INITs (1).
		Do not send ABORTs for received Out of the Blue packets (2).
	*/
	usrsctp_sysctl_set_sctp_blackhole(2);

	// TODO: ?
	usrsctp_sysctl_set_sctp_no_csum_on_loopback(0);

	/*
     // Disable the Explicit Congestion Notification extension
     usrsctp_sysctl_set_sctp_ecn_enable(0);

     // Disable the Address Reconfiguration extension
     usrsctp_sysctl_set_sctp_asconf_enable(0);

     // Disable the Authentication extension
     usrsctp_sysctl_set_sctp_auth_enable(0);

     // Disable the NR-SACK extension (not standardised)
     usrsctp_sysctl_set_sctp_nrsack_enable(0);

     // Disable the Packet Drop Report extension (not standardised)
     usrsctp_sysctl_set_sctp_pktdrop_enable(0);

     // Enable the Partial Reliability extension
     usrsctp_sysctl_set_sctp_pr_enable(1);

     // Set amount of incoming streams
     usrsctp_sysctl_set_sctp_nr_incoming_streams_default((uint32_t) n_channels);

     // Set amount of outgoing streams
     usrsctp_sysctl_set_sctp_nr_outgoing_streams_default((uint32_t) n_channels);

     // Enable interleaving messages for different streams (incoming)
     // See: https://tools.ietf.org/html/rfc6458#section-8.1.20
     usrsctp_sysctl_set_sctp_default_frag_interleave(2);
	*/

	/* create SCTP socket */
	using recv_cb_type = int (*)(struct socket*, union sctp_sockstore, void*, size_t, struct sctp_rcvinfo, int, void*);
	using send_cb_type = int (*)(struct socket *sock, uint32_t sb_free, void* ulp_info);
	recv_cb_type r_cb {nullptr};
	send_cb_type s_cb {nullptr};
	uint32_t sb_threshold {};
	void* recv_cback_data {nullptr};

	if ((serv_sock_ = usrsctp_socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP, r_cb, s_cb, sb_threshold, recv_cback_data)) == NULL) {
		CRITICAL(strerror(errno));
		throw std::runtime_error(std::string("usrsctp_socket: ") + strerror(errno));
	}

	/* subscribe to sctp stack events */
	uint16_t event_types[] = {	SCTP_ASSOC_CHANGE,
                       			SCTP_PEER_ADDR_CHANGE,
                       			SCTP_REMOTE_ERROR,
                       			SCTP_SEND_FAILED,
                       			SCTP_SHUTDOWN_EVENT,
                       			SCTP_ADAPTATION_INDICATION,
                       			SCTP_PARTIAL_DELIVERY_EVENT,
                       			SCTP_STREAM_RESET_EVENT,
                       			SCTP_SEND_FAILED_EVENT,
                       			SCTP_STREAM_CHANGE_EVENT
                       		};
	struct sctp_event event;
	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (auto ev_type : event_types) {
		event.se_type = ev_type;
		if (usrsctp_setsockopt(serv_sock_, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			CRITICAL("usrsctp_setsockopt SCTP_EVENT for serv_sock");
			throw std::runtime_error(std::string("setsockopt SCTP_EVENT: ") + strerror(errno));
		}
	}

	usrsctp_set_non_blocking(serv_sock_, 1);

	/* bind SCTP socket */
	struct sockaddr_in addr;
	memset((void *)&addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	addr.sin_family = AF_INET;
	addr.sin_port = htons(cfg_->sctp_port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (usrsctp_bind(serv_sock_, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
		CRITICAL(strerror(errno));
		throw std::runtime_error(std::string("usrsctp_bind: ") + strerror(errno));
	}

	initialized_ = true;
}


void ServerImpl::operator()()
{
	TRACE_func_entry(); BOOST_SCOPE_EXIT_ALL(&) { TRACE_func_left(); };

	if (not initialized_) throw std::logic_error("Server not initialized.");

	/* set listen on server socket */
	if (usrsctp_listen(serv_sock_, 1) < 0) {
		CRITICAL(strerror(errno));
		throw std::runtime_error(std::string("usrsctp_listen: ") + strerror(errno));
	}

	usrsctp_set_upcall(serv_sock_, &ServerImpl::handle_server_upcall, this);
}


void ServerImpl::stop()
{
	TRACE_func_entry(); BOOST_SCOPE_EXIT_ALL(&) { TRACE_func_left(); };

	cleanup();
}


void ServerImpl::send(std::shared_ptr<Server::IClient> c, const void* data, size_t len)
{
	c->send(data, len);
}

void ServerImpl::drop_client(std::shared_ptr<Server::IClient> c)
{
	TRACE_func_entry(); BOOST_SCOPE_EXIT_ALL(&) { TRACE_func_left(); };

	std::lock_guard<std::mutex> _ { clients_mutex_ };
	clients_.erase(std::remove_if(clients_.begin(), clients_.end(),
	 [&] (auto s_ptr) { return s_ptr->socket() == c->socket(); }), clients_.end());

	TRACE("Number of clients: " + std::to_string(clients_.size()));
}


void ServerImpl::handle_server_upcall(struct socket* serv_sock, void* arg, int)
{
	BOOST_ASSERT(arg);
	ServerImpl* s = static_cast<ServerImpl*>(arg);
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	auto cfg_ = s->cfg();
	/* from here on we can use log macros */

	TRACE_func_entry(); BOOST_SCOPE_EXIT_ALL(&) { TRACE_func_left(); };

	int events = usrsctp_get_events(serv_sock);

	if (events & SCTP_EVENT_READ)
	{
		TRACE("Accepting new connection.");

		struct sockaddr_in remote_addr;
		socklen_t addr_len = sizeof(struct sockaddr_in);
		struct socket* conn_sock;

		memset(&remote_addr, 0, sizeof(struct sockaddr_in));
		if ((conn_sock = ::usrsctp_accept(serv_sock, (struct sockaddr *) &remote_addr, &addr_len)) == NULL)
		{
			ERROR(strerror(errno));
			return;
		}


		auto new_client = s->client_factory(conn_sock);
		if (not new_client) return;
		{
			std::lock_guard<std::mutex> _ {s->clients_mutex_};
			s->clients_.push_back(new_client);
		}
		try
		{
			new_client->state(Server::IClient::State::SCTP_ACCEPTED);
			DEBUG("Accepted: " + new_client->to_string());
		}
		catch (const std::runtime_error& exc)
		{
			ERROR(std::string{"Dropping client: "} + exc.what());
			new_client->state(Server::IClient::State::PURGE);
			s->drop_client(new_client);
		}
	}

	if (events & SCTP_EVENT_ERROR) ERROR("SCTP_EVENT_ERROR on server socket.");
	if (events & SCTP_EVENT_WRITE) ERROR("SCTP_EVENT_WRITE on server socket.");
}

std::shared_ptr<Server::IClient> ServerImpl::get_client(const struct socket* sock)
{
	std::lock_guard<std::mutex> _ {clients_mutex_};

	auto it = std::find_if(clients_.cbegin(), clients_.cend(),
		[&] (const auto& s_ptr) { return s_ptr->socket() == sock; });

	if (it == clients_.cend()) throw std::runtime_error("client socket not found");
		 
	return *it;
}

/*
	handle_client_upcall is called by usrsctp engine on *client* socket event,
	such as : SCTP_EVENT_ERROR, SCTP_EVENT_WRITE, SCTP_EVENT_READ.
	handle_client_upcall is registered with any new client socket in accept thread

	struct socket* sock: client socket.
	void* arg : pointer to Server instance, supplied on new socket init.
	last int argument: supposed to be upcall_flags, haven't seen it's usage in examples
*/
void ServerImpl::handle_client_upcall(struct socket* upcall_sock, void* arg, int)
{
	BOOST_ASSERT(arg);
	ServerImpl* s = static_cast<ServerImpl*>(arg);
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	auto cfg_ = s->cfg();
	/* from here on we can use log macros */

	// TRACE_func_entry(); BOOST_SCOPE_EXIT_ALL(&) { TRACE_func_left(); };

	int events = usrsctp_get_events(upcall_sock);

	std::shared_ptr<Server::IClient> client;
	try
	{
		client = s->get_client(upcall_sock);
	}
	catch (const std::runtime_error& exc)
	{
		ERROR(exc.what());
		return;
	}

#if 0
	TRACE(([&] {
		std::string m { "Socket events: "};
		if (events & SCTP_EVENT_ERROR) {
			m += "SCTP_EVENT_ERROR";
		}
		if (events & SCTP_EVENT_WRITE) {
			m += " SCTP_EVENT_WRITE";
		}
		if (events & SCTP_EVENT_READ) {
			m += " SCTP_EVENT_READ";
		}
		return m;
	})());
#endif
	/*
		In usrsctp user_socket.c SCTP_EVENT_ERROR appears to be one of
		the available event types.
		No idea what does it mean and how to react properly.
	*/
	if (events & SCTP_EVENT_ERROR)
	{
		ERROR("SCTP_EVENT_ERROR: " + std::string(strerror(errno))
				 + " " + client->to_string());
	}

	if (events & SCTP_EVENT_WRITE)
	{
		//TRACE(std::string("SCTP_EVENT_WRITE for: ") + client->to_string());
	}

	/* client sent data */
	if (events & SCTP_EVENT_READ)
	{
		TRACE(std::string("SCTP_EVENT_READ for: ") + client->to_string());

		struct sctp_recvv_rn rn;
		memset(&rn, 0, sizeof(struct sctp_recvv_rn));
		//struct sctp_rcvinfo rcv_info;
		ssize_t n;
		size_t nbytes;
		struct sockaddr_in addr;
		int flags = 0;
		socklen_t from_len = (socklen_t) sizeof(struct sockaddr_in);
		unsigned int infotype;
		socklen_t infolen = sizeof(struct sctp_recvv_rn);
		//infolen = (socklen_t) sizeof(struct sctp_rcvinfo);
		char recv_buf[1<<16] = {0};

		/* got data or socket api notification */
		while ((n = usrsctp_recvv(upcall_sock, recv_buf, sizeof recv_buf,
										 (struct sockaddr*) &addr, &from_len, (void *) &rn,
											&infolen, &infotype, &flags)) > 0)
		{

			if (not (flags & MSG_EOR)) { /* usrsctp_recvv incomplete */
				//TRACE("usrsctp_recvv incomplete: " + std::to_string(n));
				client->sctp_msg_buff().insert(client->sctp_msg_buff().end(), recv_buf, recv_buf + n);

				flags = 0;
				memset(recv_buf, 0, sizeof recv_buf);
				//TRACE("usrsctp_recvv so far: " + std::to_string(client->sctp_msg_buff().size()));
				continue;
			} else { /* receive complete */
				if (not client->sctp_msg_buff().empty()) { /* some data already buffered. appending last chunk*/
					client->sctp_msg_buff().insert(client->sctp_msg_buff().end(), recv_buf, recv_buf + n);
				}
			}

			/*
			 Now we got full sctp message. Processing it.
			 At this point we can have message buffered in vector or in char array on a stack.
			 Unifying.
			*/
			BOOST_ASSERT(flags & MSG_EOR);
			nbytes = (client->sctp_msg_buff().empty()) ? n : client->sctp_msg_buff().size();
			void* data_buf = (client->sctp_msg_buff().empty()) ? recv_buf : client->sctp_msg_buff().data();

			/*
				enqueue copies of messages to be processed in another thread
			*/
			TRACE(((flags & MSG_NOTIFICATION) ? "Notification of length " : "SCTP msg of length ")
				+ std::to_string(nbytes) + std::string(" received."));

			try {
				sctp_msgs_.enqueue((flags & MSG_NOTIFICATION) ?
						std::make_unique<sctp::Message>(sctp::Message::Type::NOTIFICATION, client, data_buf, nbytes)
						:
						std::make_unique<sctp::Message>(sctp::Message::Type::DATA, client, data_buf, nbytes,
						 addr, rn, infotype));
			} catch (const std::runtime_error& exc) {
				ERROR(client_errno("handle_client_data", client));
			}

			client->sctp_msg_buff().clear();
			flags = 0;
		}

		/* 
			We are subscribed to all assoc notifications
			SCTP_ASSOC_CHANGE event with SCTP_SHUTDOWN_COMP,
			delivered by usrsctp and processed in notification handler 
			before we get here.
			This is the last point we deal with client.
			So we drop client here.
		 */
		if (n == 0)
		{
			DEBUG(client->to_string() + std::string(" disconnected."));
			client->close();
			s->drop_client(client);
		}

		// some socket error
		if (n < 0)
		{
			if ((errno == EAGAIN) or 
				(errno == EWOULDBLOCK) or 
				(errno == EINTR)) 
			{
				//TRACE(strerror(errno));
			}
			else
			{
				ERROR(client_errno("usrsctp_recvv: ", client));
			}
		}		
	}

	return;
}


void ServerImpl::sctp_msg_handler_loop()
{
	TRACE_func_entry(); BOOST_SCOPE_EXIT_ALL(&) { TRACE_func_left(); };

	while (true)
	{
		auto msg = sctp_msgs_.dequeue();

		/* end thread on nullptr message */
		if (not msg) break;

		ServerEvent evt;
		try
		{
			evt = msg->client->handle_message(msg);
		}
		catch (const std::runtime_error& exc)
		{
			ERROR(client_errno("handle_message", msg->client));
			continue;
		}

		if (evt.type == ServerEvent::Type::NONE) continue;

		if (evt.type == ServerEvent::Type::CLIENT_STATE)
		{
			try
			{
				msg->client->state(evt.client_state);	
			}
			catch (std::runtime_error& exc)
			{
				ERROR(exc.what());
				continue;
			}	
				
			if (cfg_->event_cback_f)
			{
				try
				{
					cfg_->event_cback_f(std::move(evt));
				} 
				catch (...)
				{
					CRITICAL("Exception in user's event_cback function");
				}
			}

			continue;
		}

		if (evt.type == ServerEvent::Type::CLIENT_SEND_POSSIBLE)
		{
			if (cfg_->event_cback_f && msg->client->state() == Server::IClient::State::SSL_CONNECTED)
			{
				try
				{
					cfg_->event_cback_f(std::move(evt));
				}
				catch (...)
				{
					CRITICAL("Exception in user's event_cback function");
				}
			}

			continue;
		}

		if ((evt.type == ServerEvent::Type::CLIENT_DATA) and (evt.client_data.size() > 0) and (cfg_->event_cback_f))
		{
			try
			{
				cfg_->event_cback_f(std::move(evt));
			} 
			catch (...)
			{
				CRITICAL("Exception in user's event_cback function");
			}

			continue;
		}
	}
}


std::ostream& operator<<(std::ostream &out, const ServerImpl& s)
{
	out << *(s.cfg_);
	return out;
}

} //namespace sctp