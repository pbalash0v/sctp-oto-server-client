#include <iostream>
#include <cstring>
#include <string>
#include <chrono>
#include <cassert>
#include <algorithm>
#include <thread>
#include <map>

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <usrsctp.h>

#include "sctp_server.h"
#include "client_sctp_message.h"


constexpr auto BUFFER_SIZE = 1 << 16;

/* bad signleton-like implementation */
std::atomic_bool SCTPServer::instance_exists_ { false };


namespace
{
	std::map<uint16_t, std::string> notification_names {
		{ SCTP_ASSOC_CHANGE, "SCTP_ASSOC_CHANGE" },
		{ SCTP_PEER_ADDR_CHANGE, "SCTP_PEER_ADDR_CHANGE" },
		{ SCTP_REMOTE_ERROR, "SCTP_REMOTE_ERROR"},
		{ SCTP_SEND_FAILED, "SCTP_SEND_FAILED"},
		{ SCTP_SHUTDOWN_EVENT, "SCTP_SHUTDOWN_EVENT"},
		{ SCTP_ADAPTATION_INDICATION, "SCTP_ADAPTATION_INDICATION"},
		{ SCTP_PARTIAL_DELIVERY_EVENT, "SCTP_PARTIAL_DELIVERY_EVENT"},
		{ SCTP_AUTHENTICATION_EVENT, "SCTP_AUTHENTICATION_EVENT"},
		{ SCTP_SENDER_DRY_EVENT, "SCTP_SENDER_DRY_EVENT"},
		{ SCTP_STREAM_RESET_EVENT, "SCTP_STREAM_RESET_EVENT"},
		{ SCTP_NOTIFICATIONS_STOPPED_EVENT, "SCTP_NOTIFICATIONS_STOPPED_EVENT"},
		{ SCTP_ASSOC_RESET_EVENT, "SCTP_ASSOC_RESET_EVENT"},
		{ SCTP_STREAM_CHANGE_EVENT, "SCTP_STREAM_CHANGE_EVENT"},
		{ SCTP_SEND_FAILED_EVENT, "SCTP_SEND_FAILED_EVENT"}
	};

	SyncQueue<std::unique_ptr<SCTPMessage>> sctp_msgs_;

	void set_thread_name(std::thread& thread, const char* name)
	{
	   auto handle = thread.native_handle();
	   pthread_setname_np(handle, name);
	}


	void _log_client_error_and_throw(const char* func, std::shared_ptr<IClient>& c,
														 bool should_throw)
	{
		auto cfg_ = c->server().cfg();

		std::string error { func };
		error += ": ";
		error += c->to_string();
		error += " ";
		error += strerror(errno);
		ERROR(error);
		if (should_throw) throw std::runtime_error(error);
	}


	void log_client_error(const char* func, std::shared_ptr<IClient>& c)
	{
		_log_client_error_and_throw(func, c, false);
	}


	void log_client_error_and_throw(const char* func, std::shared_ptr<IClient>& c)
	{
		_log_client_error_and_throw(func, c, true);
	}
}

SCTPServer::SCTPServer() : SCTPServer(std::make_shared<SCTPServer::Config>()) {}

SCTPServer::SCTPServer(std::shared_ptr<SCTPServer::Config> ptr) : cfg_(ptr)
{
	if (instance_exists_) throw std::logic_error("Singleton !"); // :(
	instance_exists_ = true;
}

std::shared_ptr<IClient> SCTPServer::client_factory(struct socket* s)
{
	return std::make_shared<Client>(s, *this, cfg_->message_size);
};

/*
	From usrsctp lib author's github on calling usrsctp_close() after usrsctp_shutdown(SHUT_RDWR):
	"...only calling usrsctp_close() has the same effect.
	However, you won't be able to receive any notifications,
	since you have closed the socket. This is normal socket API behaviour."
*/
SCTPServer::~SCTPServer()
{
	TRACE_func_entry();

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

	if (needs_force_close) {
		TRACE("before force close of clients");
		for (auto& c : clients_) {
			client_state(c, IClient::PURGE);
		}
		TRACE("force close of clients done");

		TRACE("before final usrsctp_finish loop");
		if (usrsctp_finish() != 0) {
			ERROR(std::string("usrsctp_finish failed: ") + strerror(errno));
		}
		TRACE("before usrsctp_finish loop");
	}

	TRACE("About to join sctp msgs handling thread");
	if (sctp_msg_handler_.joinable()) {
		sctp_msgs_.enqueue(std::make_unique<SCTPMessage>());
		sctp_msg_handler_.join();
	}
	TRACE("sctp msgs handling thread joined");

	instance_exists_ = false;

	TRACE_func_left();
}

/*
	(1) This closes accepting server socket, which should always succeed immediately (?).
	(2) This also sets SCTP_SRV_INITIATED_SHUTDOWN state for every connected client,
	which leads to SCTP SHUTDOWN being sent to all clients.
	In perfect scenario every connected client replys with SHUTDOWN_ACK
	which leads to notification SCTP_ASSOC_CHANGE SCTP_SHUTDOWN_COMP in a handle_client_upcall
	and finally usrsctp_recvv resulting in 0, where it is removed from clients_ vec.
*/
void SCTPServer::cleanup()
{
	TRACE_func_entry();

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
			client_state(c, IClient::SCTP_SRV_INITIATED_SHUTDOWN);
		}
		TRACE("clients shutdown done");
	}

	TRACE_func_left();
}

/* 
	usrsctp lib allows to call usrsctp_init for two simulteneously running processes
	without error (maybe there is some param exists to prevent this that I miss ?)
	This is some kind of hack to try manually creating UDP socket and see if we can do this.
	Will throw runtime_error if udp encaps port already in use.
*/
void SCTPServer::try_init_local_UDP()
{
	TRACE_func_entry();

	/* will point to the result */
	struct addrinfo* serv_info = NULL;
	/* RAII for serv_info */
	std::shared_ptr<struct addrinfo> serv_info_ptr (nullptr,
					 [&](struct addrinfo* s) { freeaddrinfo(s); });

	struct addrinfo hints;

	memset(&hints, 0, sizeof hints); // make sure the struct is empty
	hints.ai_family = AF_INET;			// IPV4 only
	hints.ai_socktype = SOCK_DGRAM;  // UDP socket
	hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

	int status;
	if ((status = getaddrinfo(NULL, std::to_string(cfg_->udp_encaps_port).c_str(),
		 &hints, &serv_info)) != 0) {
		CRITICAL(std::string("getaddrinfo: ") + gai_strerror(status));
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

	TRACE_func_left();
}

void SCTPServer::init()
{
	TRACE_func_entry();

	if (initialized_) throw std::logic_error("Server is already initialized.");

	ssl_obj_.init(cfg_->cert_filename, cfg_->key_filename);

	sctp_msg_handler_ = std::thread { &SCTPServer::sctp_msg_handler_loop, this };
	
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
	int (*receive_cb)(struct socket*, union sctp_sockstore, 
		void*, size_t, struct sctp_rcvinfo, int, void*) = NULL;
	int (*send_cb)(struct socket *sock, uint32_t sb_free)	= NULL;
	uint32_t sb_threshold = 0;
	void* recv_cback_data = NULL;

	if ((serv_sock_ = usrsctp_socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP,
		 receive_cb, send_cb, sb_threshold, recv_cback_data)) == NULL) {
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

	TRACE_func_left();
}


void SCTPServer::operator()()
{
	TRACE_func_entry();

	if (not initialized_) throw std::logic_error("Server not initialized.");

	set_thread_name(sctp_msg_handler_, "SCTP msgs");

	/* set listen on server socket */
	if (usrsctp_listen(serv_sock_, 1) < 0) {
		CRITICAL(strerror(errno));
		throw std::runtime_error(std::string("usrsctp_listen: ") + strerror(errno));
	}

	usrsctp_set_upcall(serv_sock_, &SCTPServer::handle_server_upcall, this);

	TRACE_func_left();
}


void SCTPServer::stop()
{
	TRACE_func_entry();

	cleanup();
	
	TRACE_func_left();
}


void SCTPServer::broadcast(const void* data, size_t len)
{
	TRACE_func_entry();

	std::lock_guard<std::mutex> _ { clients_mutex_ };
	for (auto& c : clients_) {
		send(c, data, len);
	}

	TRACE_func_left();
}


void SCTPServer::send(std::shared_ptr<IClient>& c, const void* data, size_t len)
{
	assert(c->state() == IClient::SSL_CONNECTED);
	send_raw(c, data, len);
}

/*
	Private. Accounts for client state.
*/
ssize_t SCTPServer::send_raw(std::shared_ptr<IClient>& c, const void* buf, size_t len)
{
	ssize_t sent = -1;

	if (c->state() != IClient::SSL_CONNECTED) {
		sent = c->send(buf, len);
	} else {
		int written = SSL_write(c->ssl, buf, len);
		if (SSL_ERROR_NONE != SSL_get_error(c->ssl, written)) {
			log_client_error_and_throw("SSL_write", c);
		}

		c->encrypted_msg_buff().clear();
		c->encrypted_msg_buff().resize(BIO_ctrl_pending(c->output_bio));

		int read = BIO_read(c->output_bio,
					 c->encrypted_msg_buff().data(), c->encrypted_msg_buff().size());
		if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
			log_client_error_and_throw("BIO_read", c);
		}

		sent = c->send(c->encrypted_msg_buff().data(), read);
	}

	if (sent < 0) {
		log_client_error_and_throw((std::string("usrsctp_sendv: ") + strerror(errno)).c_str(), c);
	}

	return sent;
}


void SCTPServer::drop_client(std::shared_ptr<IClient>& c)
{
	TRACE_func_entry();

	std::lock_guard<std::mutex> _ { clients_mutex_ };
	clients_.erase(std::remove_if(clients_.begin(), clients_.end(),
	 [&] (auto s_ptr) { return s_ptr->socket() == c->socket(); }), clients_.end());

	TRACE("Number of clients: " + std::to_string(clients_.size()));

	TRACE_func_left();
}


void SCTPServer::handle_server_upcall(struct socket* serv_sock, void* arg, int)
{
	assert(arg);
	SCTPServer* s = (SCTPServer*) arg;
	assert(s);
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	auto cfg_ = s->cfg();

	/* from here on we can use log macros */
	TRACE_func_entry();

	int events = usrsctp_get_events(serv_sock);

	if (events & SCTP_EVENT_READ) {
		struct sockaddr_in remote_addr;
		socklen_t addr_len = sizeof(struct sockaddr_in);
		struct socket* conn_sock;

		TRACE("Accepting new connection.");
		
		memset(&remote_addr, 0, sizeof(struct sockaddr_in));
		if ((conn_sock = s->usrsctp_accept(serv_sock, (struct sockaddr *) &remote_addr, &addr_len)) == NULL) {
			ERROR(strerror(errno));
			throw std::runtime_error(strerror(errno));
		}

		auto new_client = s->client_factory(conn_sock);

		{
			std::lock_guard<std::mutex> _ { s->clients_mutex_ } ;
			s->clients_.push_back(new_client);
		}

		try {
			new_client->init();
			s->client_state(new_client, IClient::SCTP_ACCEPTED);
		} catch (const std::runtime_error& exc) {
			ERROR(std::string("Dropping client: ") + exc.what());
			s->client_state(new_client, IClient::PURGE);
			s->drop_client(new_client);
		}
		
		DEBUG("Accepted: " + new_client->to_string());
	}

	if (events & SCTP_EVENT_ERROR) {
		ERROR("SCTP_EVENT_ERROR on server socket.");
	}

	if (events & SCTP_EVENT_WRITE) {
		ERROR("SCTP_EVENT_WRITE on server socket.");
	}
}

void SCTPServer::client_state(std::shared_ptr<IClient>& c, IClient::State s)
{
	c->state(s);

	if (cfg_->event_cback_f) {
		try {
			cfg_->event_cback_f(
				std::make_unique<Event>(Event::Type::CLIENT_STATE, c, s));
		} catch (...) {
			CRITICAL("Exception in user's event_cback function");
		}
	}
}

std::shared_ptr<IClient> SCTPServer::get_client(const struct socket* sock)
{
	std::lock_guard<std::mutex> _ { clients_mutex_ };

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
	void* arg : pointer to SCTPServer instance, supplied on new socket init.
	last int argument: supposed to be upcall_flags, haven't seen it's usage in examples
*/
void SCTPServer::handle_client_upcall(struct socket* upcall_sock, void* arg, int)
{
	assert(arg);
	SCTPServer* s = (SCTPServer*) arg; 
	assert(s);
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	auto cfg_ = s->cfg();
	/* from here on we can use log macros */

	//TRACE_func_entry();

	int events = usrsctp_get_events(upcall_sock);

	std::shared_ptr<IClient> client;
	try {
		client = s->get_client(upcall_sock);
	} catch (const std::runtime_error& exc) {
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
	if (events & SCTP_EVENT_ERROR) {
		ERROR("SCTP_EVENT_ERROR: " + std::string(strerror(errno))
				 + " " + client->to_string());
	}

	if (events & SCTP_EVENT_WRITE) {
		//TRACE(std::string("SCTP_EVENT_WRITE for: ") + client->to_string());
	}

	/* client sent data */
	if (events & SCTP_EVENT_READ) {
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
		char recv_buf[1<<16] = { 0 };

		/* got data or socket api notification */
		while ((n = usrsctp_recvv(upcall_sock, recv_buf, sizeof recv_buf,
										 (struct sockaddr*) &addr, &from_len, (void *) &rn,
											&infolen, &infotype, &flags)) > 0) {

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
			assert(flags & MSG_EOR);

			/*
			 Now we got full sctp message. Processing it.
			 At this point we can have message buffered in vector or in char array on a stack.
			 Unifying.
			*/
			nbytes = (client->sctp_msg_buff().empty()) ? n : client->sctp_msg_buff().size();
			void* data_buf = (client->sctp_msg_buff().empty()) ? recv_buf : client->sctp_msg_buff().data();

			/*
				We process notification in this thread 
				and just enqueue copies of client messages to be processed in another thread
			*/
			try {
				if (flags & MSG_NOTIFICATION) {
					TRACE(std::string("Notification of length ") + std::to_string(nbytes) + std::string(" received."));
					sctp_msgs_.enqueue(std::make_unique<SCTPMessage>(SCTPMessage::NOTIFICATION, client, data_buf, nbytes));
				} else {
					TRACE(std::string("SCTP msg of length ") + std::to_string(nbytes) + std::string(" received."));
					sctp_msgs_.enqueue(std::make_unique<SCTPMessage>(
						SCTPMessage::MESSAGE, client, data_buf, nbytes, addr, rn, infotype));
				}
			} catch (const std::runtime_error& exc) {
				log_client_error("handle_client_data", client);
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
		if (n == 0) {
			DEBUG(client->to_string() + std::string(" disconnected."));
			client->close();
			//usrsctp_close(client->sock);
			s->drop_client(client);
		}

		// some socket error
		if (n < 0) {
			if ((errno == EAGAIN) or 
				(errno == EWOULDBLOCK) or 
				(errno == EINTR)) {
				//TRACE(strerror(errno));
			} else {
				log_client_error("usrsctp_recvv: ", client);
			}
		}		
	}

	//TRACE_func_left();
	return;
}


void SCTPServer::sctp_msg_handler_loop()
{
	TRACE_func_entry();

	while (true) {
		auto msg = sctp_msgs_.dequeue();

		if (msg->size == 0) break;

		try {
			if (msg->type == SCTPMessage::NOTIFICATION) {
				handle_notification(msg->client, static_cast<union sctp_notification*>(msg->msg), msg->size);
			} else {
				handle_client_data(msg->client, msg->msg, msg->size, msg->addr, msg->rn, msg->infotype);
			}
		} catch (const std::runtime_error& exc) {
			log_client_error("handle_client_data", msg->client);
		}

	}

	TRACE_func_left();
}


void SCTPServer::handle_client_data(std::shared_ptr<IClient>& c, const void* buffer, size_t n, 
						const struct sockaddr_in& addr, const struct sctp_recvv_rn& rcv_info,
						unsigned int infotype)
{
	TRACE(([&]()
	{
		return std::string("client_data of size: ") +
				 std::to_string(n) + 
				 std::string(" for: ") + 
				 c->to_string();
	})());

	#define MAX_TLS_RECORD_SIZE (1 << 14)
	size_t outbuf_len = (c->state() != IClient::SSL_CONNECTED) ?
			MAX_TLS_RECORD_SIZE : n;

	c->decrypted_msg_buff().clear();
	c->decrypted_msg_buff().resize(outbuf_len);

	void* outbuf = c->decrypted_msg_buff().data();

	switch (c->state()) {
	case IClient::SCTP_CONNECTED:
	{
		TRACE("IClient::SCTP_CONNECTED");

		// got client hello etc
		int written = BIO_write(c->input_bio, buffer, n);
		if (SSL_ERROR_NONE != SSL_get_error(c->ssl, written)) {
			log_client_error_and_throw("BIO_write", c);
		}

		// we generate server hello etc
		int r = SSL_do_handshake(c->ssl);
		if (SSL_ERROR_WANT_READ != SSL_get_error(c->ssl, r)) {
			log_client_error_and_throw("SSL_do_handshake", c);
		}

		while (BIO_ctrl_pending(c->output_bio)) {
			TRACE("output BIO_ctrl_pending");

			int read = BIO_read(c->output_bio, outbuf, outbuf_len);
			if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
				log_client_error_and_throw("BIO_read", c);
			}

			ssize_t sent = c->send(outbuf, read);
			if (sent < 0) {
				log_client_error_and_throw("usrsctp_sendv", c);
			}
		}

		try {
			client_state(c, IClient::SSL_HANDSHAKING);
		} catch (const std::runtime_error& exc) {
			log_client_error_and_throw((std::string("set_state") + 
				std::string(exc.what())).c_str(), c);
		}
	}
	break;

	case IClient::SSL_HANDSHAKING:
	{
		TRACE("IClient::SSL_HANDSHAKING");

		int written = BIO_write(c->input_bio, buffer, n);
		if (SSL_ERROR_NONE != SSL_get_error(c->ssl, written)) {
			log_client_error_and_throw("BIO_write", c);
		}

		int r = SSL_do_handshake(c->ssl);

		if (not SSL_is_init_finished(c->ssl)) {
			if (SSL_ERROR_WANT_READ == SSL_get_error(c->ssl, r) and BIO_ctrl_pending(c->output_bio)) {
				int read = BIO_read(c->output_bio, outbuf, outbuf_len);
				if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
					log_client_error_and_throw("BIO_read", c);
				}

				ssize_t sent = c->send(outbuf, read);
				if (sent < 0) {
					log_client_error_and_throw("usrsctp_sendv", c);
				}
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(c->ssl, r) and BIO_ctrl_pending(c->output_bio)) {
				int read = BIO_read(c->output_bio, outbuf, outbuf_len);						
				if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
					log_client_error_and_throw("BIO_read", c);
				}

				ssize_t sent = c->send(outbuf, read);
				if (sent < 0) {
					log_client_error_and_throw("usrsctp_sendv", c);
				}

				try {
					client_state(c, IClient::SSL_CONNECTED);
				} catch (const std::runtime_error& exc) {
					log_client_error_and_throw((std::string("set_state") + 
						std::string(exc.what())).c_str(), c);
				}						
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(c->ssl, r) and not BIO_ctrl_pending(c->output_bio)) {
				try {
					client_state(c, IClient::SSL_CONNECTED);
				} catch (const std::runtime_error& exc) {
					log_client_error_and_throw((std::string("set_state") + 
						std::string(exc.what())).c_str(), c);
				}						
				break;
			}				
		} else {
			while (BIO_ctrl_pending(c->output_bio)) {
				TRACE("output BIO_ctrl_pending");

				int read = BIO_read(c->output_bio, outbuf, outbuf_len);
				if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
					log_client_error_and_throw("BIO_read", c);
				}

				ssize_t sent = c->send(outbuf, read);
				if (sent < 0) {
					log_client_error_and_throw("usrsctp_sendv", c);
				}
			}

			try {
				client_state(c, IClient::SSL_CONNECTED);
			} catch (const std::runtime_error& exc) {
				log_client_error_and_throw((std::string("set_state") + 
					std::string(exc.what())).c_str(), c);
			}
			break;
		}
	}
	break;

	case IClient::SSL_CONNECTED:
	{
		TRACE(std::string("encrypted message length n: ") + std::to_string(n));

		size_t total_decrypted_message_size = 0;

		int written = BIO_write(c->input_bio, buffer, n);
		if (SSL_ERROR_NONE != SSL_get_error(c->ssl, written)) {
			log_client_error_and_throw("BIO_write", c);
		}

		int read = -1;
		while (BIO_ctrl_pending(c->input_bio)) {
			read = SSL_read(c->ssl, static_cast<char*>(outbuf) + total_decrypted_message_size, MAX_TLS_RECORD_SIZE);
			TRACE(std::string("SSL read: ") + std::to_string(read));

			if (read == 0 and SSL_ERROR_ZERO_RETURN == SSL_get_error(c->ssl, read)) {
				DEBUG("SSL_ERROR_ZERO_RETURN");
				client_state(c, IClient::SSL_SHUTDOWN);
				break;
			}

			if (read < 0 and SSL_ERROR_WANT_READ == SSL_get_error(c->ssl, read)) {
				TRACE("SSL_ERROR_WANT_READ");
				break;
			}

			if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
				log_client_error_and_throw("SSL_read", c);
			}

			total_decrypted_message_size += read;
		} 


		if (read > 0) TRACE(([&]
		{
			char message[BUFFER_SIZE] = {'\0'};

			char name[INET_ADDRSTRLEN] = {'\0'};

			if (infotype == SCTP_RECVV_RCVINFO) {
				snprintf(message, sizeof message,
							"Msg %s of length %llu received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u.",
							(char*) outbuf,
							(unsigned long long) total_decrypted_message_size,
							inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN),
							ntohs(addr.sin_port),
							rcv_info.recvv_rcvinfo.rcv_sid,	rcv_info.recvv_rcvinfo.rcv_ssn,
							rcv_info.recvv_rcvinfo.rcv_tsn,
							ntohl(rcv_info.recvv_rcvinfo.rcv_ppid), rcv_info.recvv_rcvinfo.rcv_context);
			} else {
				if (n < 30) 
					snprintf(message, sizeof message, "Msg %s of length %llu received from %s:%u.",
						(char*) outbuf,
						(unsigned long long) total_decrypted_message_size,
						inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN),
						ntohs(addr.sin_port));
				else 
					snprintf(message, sizeof message, "Msg of length %llu received from %s:%u",
						(unsigned long long) total_decrypted_message_size,
						inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN),
						ntohs(addr.sin_port));						
			}

			return std::string(message);
		})());
		
		/* pass data to user */
		if (cfg_->event_cback_f and (read >0)) {
			try {
				cfg_->event_cback_f(
					std::make_unique<Event>(Event::Type::CLIENT_DATA, c,
					 std::make_unique<Data>(outbuf, total_decrypted_message_size)));
			} catch (const std::runtime_error& exc) {
				ERROR(exc.what());				
			} catch (...) {
				CRITICAL("Exception in user's event_cback function");
			}
		}
	}
	break;

	case IClient::SSL_SHUTDOWN:
		break;

	default:
		log_client_error_and_throw("Unknown client state !", c);
	break;
	} //end of switch
}


/*
	Functions to handle assoc notifications
*/
void SCTPServer::handle_association_change_event(std::shared_ptr<IClient>& c, struct sctp_assoc_change* sac)
{
	unsigned int i, n;

	auto log_message = ([&]
		{
			std::string message { "Association change " };

			switch (sac->sac_state) {
				case SCTP_COMM_UP:
					message += "SCTP_COMM_UP";
					break;
				case SCTP_COMM_LOST:
					message += "SCTP_COMM_LOST";
					break;
				case SCTP_RESTART:
					message += "SCTP_RESTART";
					break;
				case SCTP_SHUTDOWN_COMP:
					message += "SCTP_SHUTDOWN_COMP";
					break;
				case SCTP_CANT_STR_ASSOC:
					message += "SCTP_CANT_STR_ASSOC";
					break;
				default:
					message += "UNKNOWN";
					break;
			}

			message += ", streams (in/out) = (";
			message += std::to_string(sac->sac_inbound_streams);
			message += "/";
			message += std::to_string(sac->sac_outbound_streams);
			message += ")";

			n = sac->sac_length - sizeof(struct sctp_assoc_change);

			if (((sac->sac_state == SCTP_COMM_UP) or
			     (sac->sac_state == SCTP_RESTART)) and (n > 0)) {
				message += ", supports";
				for (i = 0; i < n; i++) {
					switch (sac->sac_info[i]) {
					case SCTP_ASSOC_SUPPORTS_PR:
						message += " PR";
						break;
					case SCTP_ASSOC_SUPPORTS_AUTH:
						message += " AUTH";
						break;
					case SCTP_ASSOC_SUPPORTS_ASCONF:
						message += " ASCONF";
						break;
					case SCTP_ASSOC_SUPPORTS_MULTIBUF:
						message += " MULTIBUF";
						break;
					case SCTP_ASSOC_SUPPORTS_RE_CONFIG:
						message += " RE-CONFIG";
						break;
					default:
						message += " UNKNOWN(0x";
						message += std::to_string(sac->sac_info[i]);
						message += ")";
						break;
					}
				}
			} else if (((sac->sac_state == SCTP_COMM_LOST) or
			            (sac->sac_state == SCTP_CANT_STR_ASSOC)) and (n > 0)) {
				message += ", ABORT =";
				for (i = 0; i < n; i++) {
					message += " 0x";
					message += std::to_string(sac->sac_info[i]);
				}
			}

			message += ".";

			return message;
		})();
	TRACE(log_message);

	/*
		Association change handling
	*/
	switch (sac->sac_state) {
		case SCTP_COMM_UP:
			try {
				client_state(c, IClient::SCTP_CONNECTED);
			} catch (const std::runtime_error& exc) {
				ERROR(std::string("Dropping client: ") + exc.what());
				client_state(c, IClient::PURGE);
				return;
			}
			DEBUG("Connected: " + c->to_string());
			break;
		case SCTP_COMM_LOST:
			break;
		case SCTP_RESTART:
			break;
		case SCTP_SHUTDOWN_COMP:
			try {
				client_state(c, IClient::SCTP_SHUTDOWN_CMPLT);
			} catch (const std::runtime_error& exc) {
				ERROR(std::string("Dropping client: ") + exc.what());
				client_state(c, IClient::PURGE);
				return;
			}		
			break;
		case SCTP_CANT_STR_ASSOC:
			break;
		default:
			break;
	}

	return;
}

static void handle_peer_address_change_event(std::shared_ptr<IClient>& c, struct sctp_paddr_change* spc)
{
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	auto cfg_ = c->server().cfg();
	/* from here on we can use log macros */

	char addr_buf[INET6_ADDRSTRLEN];
	const char* addr;
	char buf[BUFFER_SIZE] = { '\0' };
	struct sockaddr_in *sin;
	struct sockaddr_in6* sin6;
	struct sockaddr_conn* sconn;

	switch (spc->spc_aaddr.ss_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)&spc->spc_aaddr;
			addr = inet_ntop(AF_INET, &sin->sin_addr, addr_buf, INET_ADDRSTRLEN);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&spc->spc_aaddr;
			addr = inet_ntop(AF_INET6, &sin6->sin6_addr, addr_buf, INET6_ADDRSTRLEN);
			break;
		case AF_CONN:
			sconn = (struct sockaddr_conn *)&spc->spc_aaddr;
			snprintf(addr_buf, INET6_ADDRSTRLEN, "%p", sconn->sconn_addr);
			addr = addr_buf;
			break;
		default:
			snprintf(addr_buf, INET6_ADDRSTRLEN, "Unknown family %d", spc->spc_aaddr.ss_family);
			addr = addr_buf;
			break;
	}

	int written = snprintf(buf, sizeof buf, "Peer address %s is now ", addr);

	switch (spc->spc_state) {
		case SCTP_ADDR_AVAILABLE:
			written += snprintf(buf + written , sizeof(buf) - written, "SCTP_ADDR_AVAILABLE");
			break;
		case SCTP_ADDR_UNREACHABLE:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_UNREACHABLE");
			break;
		case SCTP_ADDR_REMOVED:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_REMOVED");
			break;
		case SCTP_ADDR_ADDED:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_ADDED");
			break;
		case SCTP_ADDR_MADE_PRIM:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_MADE_PRIM");
			break;
		case SCTP_ADDR_CONFIRMED:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_CONFIRMED");
			break;
		default:
			written += snprintf(buf + written,  sizeof(buf) - written, "UNKNOWN");
			break;
	}

	snprintf(buf + written, sizeof(buf) - written, " (error = 0x%08x).", spc->spc_error);

	DEBUG(buf);
	return;
}

static void handle_send_failed_event(std::shared_ptr<IClient>& c, struct sctp_send_failed_event* ssfe)
{
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	auto cfg_ = c->server().cfg();
	/* from here on we can use log macros */

	size_t i, n;

	char buf[BUFFER_SIZE] = { '\0' };

	int written	= 0;
	if (ssfe->ssfe_flags & SCTP_DATA_UNSENT) {
		written += snprintf(buf + written, sizeof(buf)-written, "Unsent ");
	}

	if (ssfe->ssfe_flags & SCTP_DATA_SENT) {
		written += snprintf(buf + written, sizeof(buf)-written, "Sent ");
	}

	if (ssfe->ssfe_flags & ~(SCTP_DATA_SENT | SCTP_DATA_UNSENT)) {
		written += snprintf(buf + written, sizeof(buf)-written, "(flags = %x) ", ssfe->ssfe_flags);
	}

	written += snprintf(buf + written, sizeof(buf)-written,
			 "message with PPID = %u, SID = %u, flags: 0x%04x due to error = 0x%08x",
	       ntohl(ssfe->ssfe_info.snd_ppid), ssfe->ssfe_info.snd_sid,
	       ssfe->ssfe_info.snd_flags, ssfe->ssfe_error);

	n = ssfe->ssfe_length - sizeof(struct sctp_send_failed_event);
	for (i = 0; i < n; i++) {
		written += snprintf(buf + written, sizeof(buf)-written, " 0x%02x", ssfe->ssfe_data[i]);
	}

	written += snprintf(buf + written, sizeof(buf)-written, ".\n");
	
	DEBUG(buf);

	return;
}

static void handle_adaptation_indication(std::shared_ptr<IClient>& c, struct sctp_adaptation_event* sai)
{
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	auto cfg_ = c->server().cfg();
	/* from here on we can use log macros */

	char buf[BUFFER_SIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Adaptation indication: %x.\n", sai-> sai_adaptation_ind);
	DEBUG(buf);
	return;
}

static void handle_shutdown_event(std::shared_ptr<IClient>& c, struct sctp_shutdown_event*)
{
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	auto cfg_ = c->server().cfg();
	/* from here on we can use log macros */

	char buf[BUFFER_SIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Shutdown event.");
	DEBUG(buf);
	/* XXX: notify all channels. */
	return;
}

static void handle_stream_reset_event(std::shared_ptr<IClient>& c, struct sctp_stream_reset_event* strrst)
{
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	auto cfg_ = c->server().cfg();
	/* from here on we can use log macros */

	uint32_t n, i;

	n = (strrst->strreset_length - sizeof(struct sctp_stream_reset_event)) / sizeof(uint16_t);

	char buf[BUFFER_SIZE] = { '\0' };
	int written = snprintf(buf, sizeof buf, "Stream reset event: flags = %x, ", strrst->strreset_flags);

	if (strrst->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) {
		if (strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
			written += snprintf(buf + written, sizeof(buf)-written, "incoming/");
		}
		written += snprintf(buf + written, sizeof(buf)-written, "incoming ");
	}
	if (strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
		written += snprintf(buf + written, sizeof(buf)-written, "outgoing ");
	}

	written += snprintf(buf + written, sizeof(buf)-written, "stream ids = ");
	for (i = 0; i < n; i++) {
		if (i > 0) {
			written += snprintf(buf + written, sizeof(buf)-written, ", ");
		}
		written += snprintf(buf + written, sizeof(buf)-written, "%d", strrst->strreset_stream_list[i]);
	}

	written += snprintf(buf + written, sizeof(buf)-written, ".\n");

	DEBUG(buf);

	return;
}

static void handle_stream_change_event(std::shared_ptr<IClient>& c, struct sctp_stream_change_event* strchg)
{
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	auto cfg_ = c->server().cfg();
	/* from here on we can use log macros */

	char buf[BUFFER_SIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Stream change event: streams (in/out) = (%u/%u), flags = %x.\n",
	       strchg->strchange_instrms, strchg->strchange_outstrms, strchg->strchange_flags);
	DEBUG(buf);

	return;
}

static void handle_remote_error_event(std::shared_ptr<IClient>& c, struct sctp_remote_error* sre)
{
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	auto cfg_ = c->server().cfg();
	/* from here on we can use log macros */

	size_t i, n;

	n = sre->sre_length - sizeof(struct sctp_remote_error);

	int written = 0;
	char buf[BUFFER_SIZE] = { '\0' };
	written = snprintf(buf, sizeof buf, "Remote Error (error = 0x%04x): ", sre->sre_error);
	for (i = 0; i < n; i++) {
		written += snprintf(buf + written, sizeof buf - written, " 0x%02x", sre-> sre_data[i]);
	}

	DEBUG(std::string(buf) + ".\n");

	return;
}

static void handle_sender_dry_event(std::shared_ptr<IClient>& c, struct sctp_sender_dry_event*)
{
	auto cfg_ = c->server().cfg();

	if (cfg_->event_cback_f) {
		try {
			cfg_->event_cback_f(
				std::make_unique<Event>(Event::Type::CLIENT_SEND_POSSIBLE, c));
		} catch (...) {
			CRITICAL("Exception in user's event_cback function");
		}
	}
}

void SCTPServer::handle_notification(std::shared_ptr<IClient>& c, union sctp_notification* notif, size_t n)
{
	TRACE_func_entry();

	if (notif->sn_header.sn_length != (uint32_t) n) {
		WARNING("notif->sn_header.sn_length != n");
		return;
	}

	TRACE("handle_notification: " + notification_names[notif->sn_header.sn_type]);

	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		handle_association_change_event(c, &(notif->sn_assoc_change));
		break;
	case SCTP_PEER_ADDR_CHANGE:
		handle_peer_address_change_event(c, &(notif->sn_paddr_change));
		break;
	case SCTP_REMOTE_ERROR:
		handle_remote_error_event(c, &(notif->sn_remote_error));
		break;
	case SCTP_SHUTDOWN_EVENT:
		handle_shutdown_event(c, &(notif->sn_shutdown_event));
		break;
	case SCTP_ADAPTATION_INDICATION:
		handle_adaptation_indication(c, &(notif->sn_adaptation_event));
		break;

	case SCTP_SENDER_DRY_EVENT:
		handle_sender_dry_event(c, &(notif->sn_sender_dry_event));
		break;

	case SCTP_SEND_FAILED_EVENT:
		handle_send_failed_event(c, &(notif->sn_send_failed_event));
		break;
	case SCTP_STREAM_RESET_EVENT:
		handle_stream_reset_event(c, &(notif->sn_strreset_event));
		break;
	case SCTP_STREAM_CHANGE_EVENT:
		handle_stream_change_event(c, &(notif->sn_strchange_event));
		break;
	case SCTP_NOTIFICATIONS_STOPPED_EVENT:
	case SCTP_ASSOC_RESET_EVENT:
	case SCTP_PARTIAL_DELIVERY_EVENT:
	case SCTP_AUTHENTICATION_EVENT:
		break;		
	default:
		ERROR("Unknown notification type !");
		break;
	}

	TRACE_func_left();
}



/* testing "seams". C lib function wrappers */
inline struct socket* SCTPServer::usrsctp_socket(int domain, int type, int protocol,
               int (*receive_cb)(struct socket *sock, union sctp_sockstore addr, void *data,
                                 size_t datalen, struct sctp_rcvinfo, int flags, void *ulp_info),
               int (*send_cb)(struct socket *sock, uint32_t sb_free),
               uint32_t sb_threshold, void *ulp_info)
{
	return ::usrsctp_socket(domain, type, protocol,receive_cb, send_cb, sb_threshold, ulp_info);
};
inline int SCTPServer::usrsctp_bind(struct socket* so, struct sockaddr* name, socklen_t namelen)
{
	return ::usrsctp_bind(so, name, namelen);
};
inline int SCTPServer::usrsctp_listen(struct socket* so, int backlog)
{
	return ::usrsctp_listen(so, backlog);
};
inline struct socket* SCTPServer::usrsctp_accept(struct socket* so, struct sockaddr* aname, socklen_t* anamelen)
{
	return ::usrsctp_accept(so, aname, anamelen);
};



std::ostream& operator<<(std::ostream& out, const SCTPServer::Config& c)
{
	out << "UDP encaps port: " << std::to_string(c.udp_encaps_port) << ", ";
	out << "SCTP port: " << std::to_string(c.sctp_port) << ", ";	
	out << "Event callback: " << (c.event_cback_f == nullptr ? "not set" : "set") << ", ";
	out << "Debug callback: " << (c.debug_f == nullptr ? "not set" : "set") << ", ";
	out << "SSL certificate: " << c.cert_filename << ", ";
	out << "SSL key: " << c.key_filename;	
	return out;
}

std::ostream& operator<<(std::ostream &out, const SCTPServer &s)
{
	out << *(s.cfg_);
	return out;
}
