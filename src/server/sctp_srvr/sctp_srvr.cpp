#include <iostream>
#include <cstring>
#include <string>
#include <chrono>
#include <cassert>
#include <algorithm>

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#include <usrsctp.h>

#include "sctp_srvr.h"



#define BUFFERSIZE (1<<16)

static void _log_client_error_and_throw(const char* func, std::shared_ptr<IClient>& c,
													 bool should_throw)
{
	std::shared_ptr<SCTPServer::Config> cfg_ = c->server_.cfg_;

	std::string error { func };
	error += ": ";
	error += c->to_string();
	error += " ";
	error += strerror(errno);
	ERROR(error);
	if (should_throw) throw std::runtime_error(error);
}

static void log_client_error(const char* func, std::shared_ptr<IClient>& c)
{
	_log_client_error_and_throw(func, c, false);
}

static void log_client_error_and_throw(const char* func, std::shared_ptr<IClient>& c)
{
	_log_client_error_and_throw(func, c, true);
}



std::shared_ptr<SCTPServer> SCTPServer::s_ = std::make_shared<SCTPServer>();

constexpr auto BUFFER_SIZE = 1 << 16;

/* 
	function wakeup_one is not in any usrsctp lib header 
	(but also is not static)
	hence need to explicitly declare it to use 
	for cancelling stcp_accept blocking call
*/
extern "C" {
	void wakeup_one(void *ident);
}




SCTPServer::SCTPServer() : SCTPServer(std::make_shared<SCTPServer::Config>()) {}

SCTPServer::SCTPServer(std::shared_ptr<SCTPServer::Config> ptr) : cfg_(ptr)
{
	cfg_->client_factory = [&] (struct socket* s, SCTPServer&) {
		return std::make_shared<Client>(s, *this);
	};
}


SCTPServer::~SCTPServer()
{
	TRACE_func_entry();

	cleanup();

	DEBUG("before usrsctp_finish loop");
	while (usrsctp_finish() != 0) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	TRACE_func_left();
}


void SCTPServer::init()
{
	TRACE_func_entry();

	ssl_obj_.init(cfg_->cert_filename, cfg_->key_filename);

	usrsctp_init(cfg_->udp_encaps_port,
		/* should udp socket be handled by usrsctp */ NULL, /* SCTP lib's debug cback */ NULL);

	usrsctp_sysctl_set_sctp_blackhole(2); // TODO: ?
	usrsctp_sysctl_set_sctp_no_csum_on_loopback(0); // TODO: ?

	int (*receive_cb)(struct socket*, union sctp_sockstore, 
		void*, size_t, struct sctp_rcvinfo, int, void*) = NULL;
	int (*send_cb)(struct socket *sock, uint32_t sb_free)	= NULL;
	uint32_t sb_threshold = 0;
	void* recv_cback_data = NULL;

	/* create SCTP socket */
	if ((serv_sock_ = usrsctp_socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP,
		 receive_cb = NULL, send_cb = NULL, sb_threshold, recv_cback_data = NULL)) == NULL) {
		CRITICAL(strerror(errno));
		throw std::runtime_error(std::string("usrsctp_socket: ") + strerror(errno));
	}

	uint16_t event_types[] = {	SCTP_ASSOC_CHANGE,
                       			SCTP_PEER_ADDR_CHANGE,
                       			SCTP_REMOTE_ERROR,
                       			SCTP_SHUTDOWN_EVENT,
                       			SCTP_ADAPTATION_INDICATION,
                       			SCTP_PARTIAL_DELIVERY_EVENT
                       		};
	struct sctp_event event;
	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (auto ev_type : event_types) {
		event.se_type = ev_type;
		if (usrsctp_setsockopt(serv_sock_, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			ERROR("usrsctp_setsockopt SCTP_EVENT for serv_sock");
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

	/* set listen on server socket*/
	if (usrsctp_listen(serv_sock_, 1) < 0) {
		CRITICAL(strerror(errno));
		throw std::runtime_error(std::string("usrsctp_listen: ") + strerror(errno));
	}

	usrsctp_set_upcall(serv_sock_, &SCTPServer::handle_serv_upcall, this);

	initialized = true;

	TRACE_func_left();
}



void SCTPServer::run()
{
	if (not initialized) throw std::logic_error("Server not initialized.");
	//accept_thr_ = std::thread(&SCTPServer::accept_loop, this);
}


void SCTPServer::cleanup()
{
	TRACE_func_entry();

	std::lock_guard<std::mutex> lock(clients_mutex_);

	if (serv_sock_) {
		TRACE("before serv_sock_ usrsctp_shutdown");
		usrsctp_shutdown(serv_sock_, SHUT_RDWR);
	}

	/* signal on usrsctp lib's accept thread cond variable
		no idea how to unblock blocking accept in any other way */
	wakeup_one(NULL);
	TRACE("usrsctp_shutdown done");

	/* Stop and clean up on accepting thread */
	if (accept_thr_.joinable()) {
		TRACE("before accept_thr_.join()");
		accept_thr_.join();
		TRACE("accept_thr_ joined");
	}

	if (serv_sock_) {
		TRACE("server socket usrsctp_close");
		usrsctp_close(serv_sock_);
		TRACE("server socket closed");
	}

	/* shutdown and cleanup clients */
	TRACE("before clients shutdown");
	for (auto c : clients_) {
		c->set_state(Client::PURGE);
	}
	clients_.clear();
	TRACE("clients shutdown done");


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

	std::lock_guard<std::mutex> lock(clients_mutex_);
	for (auto c : clients_) {
		send(c, data, len);
	}

	TRACE_func_left();
}


void SCTPServer::broadcast(const std::string& message)
{
	broadcast(message.c_str(), message.size());
}


void SCTPServer::send(std::shared_ptr<IClient>& c, const void* data, size_t len)
{
	if (c->state == Client::SSL_CONNECTED) {
		send_raw(c, data, len);
	}
}


void SCTPServer::send(std::shared_ptr<IClient>& c, const std::string& message)
{
	send(c, message.c_str(), message.size());
}


/*
	Private. Accounts for client state.
*/
ssize_t SCTPServer::send_raw(std::shared_ptr<IClient>& c, const void* buf, size_t len)
{
	ssize_t sent = -1;

	if (c->state < Client::SSL_CONNECTED) {
		// addrs - NULL for connected socket
		// addrcnt: Number of addresses.
		// As at most one address is supported, addrcnt is 0 if addrs is NULL and 1 otherwise.
		sent = usrsctp_sendv(c->sock, buf, len,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
	} else {
		int written = SSL_write(c->ssl, buf, len);
		if (SSL_ERROR_NONE != SSL_get_error(c->ssl, written)) {
			log_client_error_and_throw("SSL_write", c);
		}		

		char outbuf[BUFFER_SIZE] = { 0 };
		int read = BIO_read(c->output_bio, outbuf, sizeof(outbuf));
		if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
			log_client_error_and_throw("BIO_read", c);
		}		

		sent = usrsctp_sendv(c->sock, outbuf, read,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
	}

	if (sent < 0) {
		log_client_error_and_throw((std::string("usrsctp_sendv: ") + strerror(errno)).c_str(), c);
	}

	return sent;
}


/*
	Accepting new connections with blocking sctp accept.
	Runs in own thread.
*/
void SCTPServer::accept_loop()
{
	TRACE_func_entry();

	struct sockaddr_in remote_addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);
	struct socket* conn_sock;

	try {
		while (true) {
			DEBUG("Accepting new connections...");
			
			memset(&remote_addr, 0, sizeof(struct sockaddr_in));
			if ((conn_sock = usrsctp_accept(serv_sock_, (struct sockaddr *) &remote_addr, &addr_len)) == NULL) {
				DEBUG(strerror(errno));
				throw std::runtime_error(strerror(errno));
			}

			DEBUG("New connection accepted.");

			{
				std::lock_guard<std::mutex> lock(clients_mutex_);

				clients_.push_back(cfg_->client_factory(conn_sock, *this));

				try {
					clients_.back()->init();
					clients_.back()->set_state(Client::SCTP_ACCEPTED);
				} catch (const std::runtime_error& exc) {
					ERROR(std::string("Dropping client: ") + exc.what());
					clients_.back()->set_state(Client::PURGE);
					drop_client(clients_.back());
					continue;
				}

				INFO("Accepted: " + clients_.back()->to_string());
			}
		}

	/* at this point accept loop has ended
		but there still could be client to serve */
	} catch (const std::runtime_error& exc) {
		CRITICAL(std::string("Not accepting new clients anymore: ") + exc.what());
	}

	TRACE_func_left();
}


void SCTPServer::drop_client(std::shared_ptr<IClient>& c)
{
	std::lock_guard<std::mutex> lock(clients_mutex_);
	clients_.erase(std::remove_if(clients_.begin(), clients_.end(),
	 [&] (auto s_ptr) { return s_ptr->sock == c->sock;}), clients_.end());
}




void SCTPServer::handle_serv_upcall(struct socket* serv_sock, void* arg, int)
{
	SCTPServer* s = (SCTPServer*) arg; assert(s);
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	std::shared_ptr<SCTPServer::Config> cfg_ = s->cfg_;

	/* from here on we can use log macros */
	TRACE_func_entry();

	int events = usrsctp_get_events(serv_sock);

	if (events & SCTP_EVENT_ERROR) {
		ERROR("SCTP_EVENT_ERROR on server socket.");
	}
	if (events & SCTP_EVENT_WRITE) {
		ERROR("SCTP_EVENT_WRITE on server socket.");
	}

	if (events & SCTP_EVENT_READ) {
		struct sockaddr_in remote_addr;
		socklen_t addr_len = sizeof(struct sockaddr_in);
		struct socket* conn_sock;

		DEBUG("Accepting new connection.");
		
		memset(&remote_addr, 0, sizeof(struct sockaddr_in));
		if ((conn_sock = s->usrsctp_accept(serv_sock, (struct sockaddr *) &remote_addr, &addr_len)) == NULL) {
			DEBUG(strerror(errno));
			throw std::runtime_error(strerror(errno));
		}

		DEBUG("New connection accepted.");

		{
			std::lock_guard<std::mutex> lock(s->clients_mutex_);

			auto new_client = cfg_->client_factory(conn_sock, *s);
			s->clients_.push_back(new_client);

			try {
				new_client->init();
				new_client->set_state(Client::SCTP_ACCEPTED);
			} catch (const std::runtime_error& exc) {
				ERROR(std::string("Dropping client: ") + exc.what());
				new_client->set_state(Client::PURGE);
				s->drop_client(new_client);
			}
			
			INFO("Accepted: " + new_client->to_string());
		}
	}
}


/*
	handle_upcall is called by usrsctp engine on *client* socket event,
	such as : SCTP_EVENT_ERROR, SCTP_EVENT_WRITE, SCTP_EVENT_READ.
	handle_upcall is registered with any new client socket in accept thread

	struct socket* sock: client socket.
	void* arg : pointer to SCTPServer instance, supplied on new socket init.
	last int argument: supposed to be upcall_flags, haven't seen it's usage in examples
*/
void SCTPServer::handle_upcall(struct socket* upcall_sock, void* arg, int)
{
	SCTPServer* s = (SCTPServer*) arg; assert(s);

	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	std::shared_ptr<SCTPServer::Config> cfg_ = s->cfg_;
	
	/* from here on we can use log macros */
	TRACE_func_entry();

	auto& clients = s->clients_;

	std::shared_ptr<IClient> c;
	{
		std::lock_guard<std::mutex> lock(s->clients_mutex_);

		auto it = std::find_if(clients.cbegin(), clients.cend(), [&] (const auto& s_ptr) {
			return s_ptr->sock == upcall_sock;
		});

		if (it != clients.cend()) {
			c = *it;
		} else {
			ERROR("handle_upcall: client socket not found ?");
			return;
		}
	}
	

	int events = usrsctp_get_events(upcall_sock);

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
	TRACE(m);

	/*
		In usrsctp user_socket.c SCTP_EVENT_ERROR appears to be one of
		the available event types.
		No idea what does it mean.
	*/
	if (events & SCTP_EVENT_ERROR) {
		ERROR("SCTP_EVENT_ERROR: " + c->to_string());
	}

	/* client sent data */
	if (events & SCTP_EVENT_READ) {
		TRACE(std::string("SCTP_EVENT_READ for: ") + c->to_string());

		struct sctp_recvv_rn rn;
		memset(&rn, 0, sizeof(struct sctp_recvv_rn));

		//struct sctp_rcvinfo rcv_info;
		ssize_t n;
		struct sockaddr_in addr;
		void* buf = calloc(1, BUFFERSIZE);
		int flags = 0;
		socklen_t from_len = (socklen_t) sizeof(struct sockaddr_in);
		unsigned int infotype;
		socklen_t infolen = sizeof(struct sctp_recvv_rn);
		//infolen = (socklen_t) sizeof(struct sctp_rcvinfo);

		while ((n = usrsctp_recvv(upcall_sock, buf, BUFFERSIZE, (struct sockaddr*) &addr, &from_len, (void *) &rn,
								&infolen, &infotype, &flags)) > 0) {
			/* got data */
			if (n > 0) {
				if (flags & MSG_NOTIFICATION) {
					TRACE(std::string("Notification of length ") + std::to_string(n) + std::string(" received."));
					s->handle_notification(c, (union sctp_notification*) buf, n);
				} else {
					TRACE(std::string("Socket data of length ") + std::to_string(n) + std::string(" received."));
					try {
						c->server_.handle_client_data(c, buf, n, addr, rn, infotype, flags);
					} catch (const std::runtime_error& exc) {
						log_client_error("handle_client_data", c);
					}
				}
			/* client disconnected */
			} else if (n == 0) {
				ERROR(c->to_string() + std::string(" disconnected."));
				c->set_state(Client::PURGE);
				s->drop_client(c);
			/* client disconnected */
			} else { // wtf ?
				free(buf);
				log_client_error("usrsctp_recvv", c);
			}

			memset(buf, 0, BUFFERSIZE);
		}

		free(buf);
	}


	if (events & SCTP_EVENT_WRITE) {
		TRACE(std::string("SCTP_EVENT_WRITE for: ") + c->to_string());
	}

	TRACE_func_left();

	return;
}


void SCTPServer::handle_client_data(std::shared_ptr<IClient>& c, const void* buffer, ssize_t n, 
						const struct sockaddr_in& addr, const struct sctp_recvv_rn& rcv_info,
						unsigned int infotype, int flags)
{
	TRACE(std::string("handle_client_data of ") + c->to_string());

	switch (c->state) {

		case Client::SCTP_CONNECTED:
			{
				TRACE("Client::SCTP_CONNECTED");

				int written = BIO_write(c->input_bio, buffer, n);
				if (SSL_ERROR_NONE != SSL_get_error(c->ssl, written)) {
					log_client_error_and_throw("BIO_write", c);
				}

				int r = SSL_do_handshake(c->ssl);
				if (SSL_ERROR_WANT_READ != SSL_get_error(c->ssl, r)) {
					log_client_error_and_throw("SSL_do_handshake", c);
				}

				char outbuf[BUFFER_SIZE] = {0};
				int read = BIO_read(c->output_bio, outbuf, sizeof outbuf);
				if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
					log_client_error_and_throw("BIO_read", c);
				}

				ssize_t sent = usrsctp_sendv(c->sock, outbuf, read,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
				if (sent < 0) {
					log_client_error_and_throw("usrsctp_sendv", c);
				}
				try {
					c->set_state(Client::SSL_HANDSHAKING);
				} catch (const std::runtime_error& exc) {
					log_client_error_and_throw((std::string("set_state") + 
						std::string(exc.what())).c_str(), c);
				}
			}
		break;

		case Client::SSL_HANDSHAKING:
			{
				TRACE("Client::SSL_HANDSHAKING");
				char outbuf[BUFFER_SIZE] = {0};

				int written = BIO_write(c->input_bio, buffer, n);
				if (SSL_ERROR_NONE != SSL_get_error(c->ssl, written)) {
					log_client_error_and_throw("BIO_write", c);
				}

				int r = SSL_do_handshake(c->ssl);

				if (not SSL_is_init_finished(c->ssl)) {
					if (SSL_ERROR_WANT_READ == SSL_get_error(c->ssl, r) and BIO_ctrl_pending(c->output_bio)) {
						int read = BIO_read(c->output_bio, outbuf, sizeof outbuf);
						if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
							log_client_error_and_throw("BIO_read", c);
						}

						ssize_t sent = usrsctp_sendv(c->sock, outbuf, read,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
						if (sent < 0) {
							log_client_error_and_throw("usrsctp_sendv", c);
						}
						break;
					}

					if (SSL_ERROR_NONE == SSL_get_error(c->ssl, r) and BIO_ctrl_pending(c->output_bio)) {
						int read = BIO_read(c->output_bio, outbuf, sizeof outbuf);						
						if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
							log_client_error_and_throw("BIO_read", c);
						}

						ssize_t sent = usrsctp_sendv(c->sock, outbuf, read,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
						if (sent < 0) {
							log_client_error_and_throw("usrsctp_sendv", c);
						}

						try {
							c->set_state(Client::SSL_CONNECTED);
						} catch (const std::runtime_error& exc) {
							log_client_error_and_throw((std::string("set_state") + 
								std::string(exc.what())).c_str(), c);
						}						
						break;
					}

					if (SSL_ERROR_NONE == SSL_get_error(c->ssl, r) and not BIO_ctrl_pending(c->output_bio)) {
						try {
							c->set_state(Client::SSL_CONNECTED);
						} catch (const std::runtime_error& exc) {
							log_client_error_and_throw((std::string("set_state") + 
								std::string(exc.what())).c_str(), c);
						}						
						break;
					}				
				} else {
					if (BIO_ctrl_pending(c->output_bio)) {
						TRACE("output BIO_ctrl_pending");

						int read = BIO_read(c->output_bio, outbuf, sizeof outbuf);
						if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
							log_client_error_and_throw("BIO_read", c);
						}

						ssize_t sent = usrsctp_sendv(c->sock, outbuf, read,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
						if (sent < 0) {
							log_client_error_and_throw("usrsctp_sendv", c);
						}						   
					}

					try {
						c->set_state(Client::SSL_CONNECTED);
					} catch (const std::runtime_error& exc) {
						log_client_error_and_throw((std::string("set_state") + 
							std::string(exc.what())).c_str(), c);
					}
					break;
				}
			}
		break;

		case Client::SSL_CONNECTED:
			{
				TRACE("Client::SSL_CONNECTED");
				DEBUG(std::string("n: ") + std::to_string(n));

				char name[INET_ADDRSTRLEN] = {'\0'};

				int written = BIO_write(c->input_bio, buffer, n);
				if (SSL_ERROR_NONE != SSL_get_error(c->ssl, written)) {
					log_client_error_and_throw("BIO_write", c);
				}

				char outbuf[BUFFER_SIZE] = {'\0'};
				int read = SSL_read(c->ssl, outbuf, sizeof outbuf);
				if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) {
					log_client_error_and_throw("SSL_read", c);
				}

				DEBUG(std::string("read: ") + std::to_string(read));

				if (not read and SSL_ERROR_ZERO_RETURN == SSL_get_error(c->ssl, read)) {
					c->set_state(Client::SSL_SHUTDOWN);
					break;
				}

				if (read < 0 and SSL_ERROR_WANT_READ == SSL_get_error(c->ssl, read)) {
					DEBUG("SSL_ERROR_WANT_READ");
					break;
				}

				char message[BUFFER_SIZE] = {'\0'};

				if (infotype == SCTP_RECVV_RCVINFO) {
					snprintf(message, sizeof message,
								"Msg %s of length %llu received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u, complete %d.",
								(char*) outbuf,
								(unsigned long long) read,
								inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN), ntohs(addr.sin_port),
								rcv_info.recvv_rcvinfo.rcv_sid,	rcv_info.recvv_rcvinfo.rcv_ssn,	rcv_info.recvv_rcvinfo.rcv_tsn,
								ntohl(rcv_info.recvv_rcvinfo.rcv_ppid), rcv_info.recvv_rcvinfo.rcv_context,
								(flags & MSG_EOR) ? 1 : 0);
				} else {
					snprintf(message, sizeof message, "Msg %s of length %llu received from %s:%u, complete %d.",
						(char*) outbuf,
						(unsigned long long) read,
						inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN), ntohs(addr.sin_port),
						(flags & MSG_EOR) ? 1 : 0);
				}

				DEBUG(message);

				if (cfg_->data_cback_f) {
					try {
						cfg_->data_cback_f(c, outbuf);
					} catch (...) {
						CRITICAL("data_cback_f");
					}
				}
			}
		break;

		case Client::SSL_SHUTDOWN:
			break;

		default:
			log_client_error_and_throw("Unknown client state !", c);
		break;
	} //end of switch
}


/*
	Functions to handle assoc notifications
*/

static void handle_association_change_event(std::shared_ptr<IClient>& c, struct sctp_assoc_change* sac)
{
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	std::shared_ptr<SCTPServer::Config> cfg_ = (c->server_).cfg_;
	/* from here on we can use log macros */

	unsigned int i, n;

	/*
		Preapre debug message for association change
	*/
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

		DEBUG(message);
	}


	/*
		Real association change handling
	*/
	switch (sac->sac_state) {
		case SCTP_COMM_UP:
			try {
				c->set_state(Client::SCTP_CONNECTED);
			} catch (const std::runtime_error& exc) {
				ERROR(std::string("Dropping client: ") + exc.what());
				c->set_state(Client::PURGE);
				//(c->server_).drop_client(c);
				return;
			}
			INFO("Connected: " + c->to_string());		
			break;
		case SCTP_COMM_LOST:
			break;
		case SCTP_RESTART:
			break;
		case SCTP_SHUTDOWN_COMP:
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
	std::shared_ptr<SCTPServer::Config> cfg_ = (c->server_).cfg_;
	/* from here on we can use log macros */

	char addr_buf[INET6_ADDRSTRLEN];
	const char* addr;
	char buf[BUFFERSIZE] = { '\0' };
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
	std::shared_ptr<SCTPServer::Config> cfg_ = (c->server_).cfg_;
	/* from here on we can use log macros */

	size_t i, n;

	if (ssfe->ssfe_flags & SCTP_DATA_UNSENT) {
		fprintf(stderr, "Unsent ");
	}

	if (ssfe->ssfe_flags & SCTP_DATA_SENT) {
		fprintf(stderr, "Sent ");
	}

	if (ssfe->ssfe_flags & ~(SCTP_DATA_SENT | SCTP_DATA_UNSENT)) {
		fprintf(stderr, "(flags = %x) ", ssfe->ssfe_flags);
	}

	fprintf(stderr, "message with PPID = %u, SID = %u, flags: 0x%04x due to error = 0x%08x",
	       ntohl(ssfe->ssfe_info.snd_ppid), ssfe->ssfe_info.snd_sid,
	       ssfe->ssfe_info.snd_flags, ssfe->ssfe_error);

	n = ssfe->ssfe_length - sizeof(struct sctp_send_failed_event);
	for (i = 0; i < n; i++) {
		fprintf(stderr, " 0x%02x", ssfe->ssfe_data[i]);
	}

	fprintf(stderr, ".\n");
	return;
}

static void handle_adaptation_indication(std::shared_ptr<IClient>& c, struct sctp_adaptation_event* sai)
{
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	std::shared_ptr<SCTPServer::Config> cfg_ = (c->server_).cfg_;
	/* from here on we can use log macros */

	char buf[BUFFERSIZE] = { '\0' };
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
	std::shared_ptr<SCTPServer::Config> cfg_ = (c->server_).cfg_;
	/* from here on we can use log macros */

	char buf[BUFFERSIZE] = { '\0' };
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
	std::shared_ptr<SCTPServer::Config> cfg_ = (c->server_).cfg_;
	/* from here on we can use log macros */

	uint32_t n, i;

	n = (strrst->strreset_length - sizeof(struct sctp_stream_reset_event)) / sizeof(uint16_t);
	fprintf(stderr, "Stream reset event: flags = %x, ", strrst->strreset_flags);
	if (strrst->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) {
		if (strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
			fprintf(stderr, "incoming/");
		}
		fprintf(stderr, "incoming ");
	}
	if (strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
		fprintf(stderr, "outgoing ");
	}
	fprintf(stderr, "stream ids = ");
	for (i = 0; i < n; i++) {
		if (i > 0) {
			fprintf(stderr, ", ");
		}
		fprintf(stderr, "%d", strrst->strreset_stream_list[i]);
	}
	fprintf(stderr, ".\n");
	return;
}

static void handle_stream_change_event(std::shared_ptr<IClient>& c, struct sctp_stream_change_event* strchg)
{
	/* 
		log macros depend on local object named cfg_.
		Getting it here explicitly.
	*/
	std::shared_ptr<SCTPServer::Config> cfg_ = (c->server_).cfg_;
	/* from here on we can use log macros */

	char buf[BUFFERSIZE] = { '\0' };
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
	std::shared_ptr<SCTPServer::Config> cfg_ = (c->server_).cfg_;
	/* from here on we can use log macros */

	size_t i, n;

	n = sre->sre_length - sizeof(struct sctp_remote_error);

	int written = 0;
	char buf[BUFFERSIZE] = { '\0' };
	written = snprintf(buf, sizeof buf, "Remote Error (error = 0x%04x): ", sre->sre_error);
	for (i = 0; i < n; i++) {
		written += snprintf(buf + written, sizeof buf - written, " 0x%02x", sre-> sre_data[i]);
	}

	DEBUG(std::string(buf) + ".\n");

	return;
}

void SCTPServer::handle_notification(std::shared_ptr<IClient>& c, union sctp_notification* notif, size_t n)
{
	TRACE_func_entry();

	if (notif->sn_header.sn_length != (uint32_t) n) {
		return;
	}
	std::string message { "handle_notification : " };

	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		message += "SCTP_ASSOC_CHANGE";
		TRACE(message);
		handle_association_change_event(c, &(notif->sn_assoc_change));
		break;
	case SCTP_PEER_ADDR_CHANGE:
		message += "SCTP_PEER_ADDR_CHANGE";
		TRACE(message);
		handle_peer_address_change_event(c, &(notif->sn_paddr_change));
		break;
	case SCTP_REMOTE_ERROR:
		message += "SCTP_REMOTE_ERROR";
		TRACE(message);
		handle_remote_error_event(c, &(notif->sn_remote_error));
		break;
	case SCTP_SHUTDOWN_EVENT:
		message += "SCTP_SHUTDOWN_EVENT";
		TRACE(message);
		handle_shutdown_event(c, &(notif->sn_shutdown_event));
		break;
	case SCTP_ADAPTATION_INDICATION:
		message += "SCTP_ADAPTATION_INDICATION";
		TRACE(message);
		handle_adaptation_indication(c, &(notif->sn_adaptation_event));
		break;
	case SCTP_PARTIAL_DELIVERY_EVENT:
		message += "SCTP_PARTIAL_DELIVERY_EVENT\n";
		TRACE(message);
		break;
	case SCTP_AUTHENTICATION_EVENT:
		message += "SCTP_AUTHENTICATION_EVENT\n";
		TRACE(message);		
		break;
	case SCTP_SENDER_DRY_EVENT:
		message += "SCTP_SENDER_DRY_EVENT\n";
		TRACE(message);		
		break;
	case SCTP_NOTIFICATIONS_STOPPED_EVENT:
		message += "SCTP_NOTIFICATIONS_STOPPED_EVENT\n";
		TRACE(message);		
		break;
	case SCTP_SEND_FAILED_EVENT:
		message += "SCTP_SEND_FAILED_EVENT\n";
		TRACE(message);		
		handle_send_failed_event(c, &(notif->sn_send_failed_event));
		break;
	case SCTP_STREAM_RESET_EVENT:
		message += "SCTP_STREAM_RESET_EVENT\n";
		TRACE(message);
		handle_stream_reset_event(c, &(notif->sn_strreset_event));
		break;
	case SCTP_ASSOC_RESET_EVENT:
		message += "SCTP_ASSOC_RESET_EVENT\n";
		TRACE(message);
		break;
	case SCTP_STREAM_CHANGE_EVENT:
		message += "SCTP_STREAM_CHANGE_EVENT\n";
		TRACE(message);
		handle_stream_change_event(c, &(notif->sn_strchange_event));
		break;
	default:
		message += "UNKNOWN";
		ERROR(message);
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
	out << "Data callback: " << (c.data_cback_f == nullptr ? "nullptr" : "set") << ", ";
	out << "Debug callback: " << (c.debug_f == nullptr ? "nullptr" : "set") << ", ";
	out << "SSL certificate: " << c.cert_filename << ", ";
	out << "SSL key: " << c.key_filename;	
	return out;
}

std::ostream& operator<<(std::ostream &out, const SCTPServer &s)
{
	out << *(s.cfg_);
	return out;
}
