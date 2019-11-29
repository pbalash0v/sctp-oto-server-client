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

SCTPServer::SCTPServer(std::shared_ptr<SCTPServer::Config> ptr) : cfg_(ptr) {
	cfg_->client_factory = [&] (struct socket* s, SCTPServer&) {
		return std::make_shared<Client>(s, *this);
	};
}


SCTPServer::~SCTPServer() {
	TRACE_func_entry();

	cleanup();

	DEBUG("before usrsctp_finish loop");
	while (usrsctp_finish() != 0) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}

	TRACE_func_left();
}


void SCTPServer::init() {
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

	/* listen SCTP socket*/
	if (usrsctp_listen(serv_sock_, 1) < 0) {
		CRITICAL(strerror(errno));
		throw std::runtime_error(std::string("usrsctp_listen: ") + strerror(errno));
	}

	initialized = true;

	TRACE_func_left();
}



void SCTPServer::run() {
	if (not initialized) throw std::logic_error("Server not initialized.");
	accept_thr_ = std::thread(&SCTPServer::accept_loop, this);
}


void SCTPServer::cleanup() {
	TRACE_func_entry();

	std::lock_guard<std::mutex> lock(clients_mutex_);

	if (accept_thr_.joinable()) {
		/* Stop and clean up on accepting thread */
		TRACE("before serv_sock_ usrsctp_shutdown");
		usrsctp_shutdown(serv_sock_, SHUT_RDWR);

		/* signal on usrsctp lib's accept thread cond variable
			no idea how to unblock blocking accept in any other way */
		wakeup_one(NULL);
		TRACE("usrsctp_shutdown done");

		TRACE("before accept_thr_.join()");
		accept_thr_.join();
		TRACE("accept_thr_ joined");

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


void SCTPServer::stop() {
	TRACE_func_entry();

	cleanup();
	
	TRACE_func_left();
}


void SCTPServer::broadcast(const void* data, size_t len) {
	TRACE_func_entry();

	std::lock_guard<std::mutex> lock(clients_mutex_);
	for (auto c : clients_) {
		send(c, data, len);
	}

	TRACE_func_left();
}



void SCTPServer::broadcast(const std::string& message) {
	broadcast(message.c_str(), message.size());
}


void SCTPServer::send(std::shared_ptr<IClient>& c, const void* data, size_t len) {
	if (c->state == Client::SSL_CONNECTED) {
		send_raw(c, data, len);
	}
}


void SCTPServer::send(std::shared_ptr<IClient>& c, const std::string& message) {
	send(c, message.c_str(), message.size());
}


/*
	Private. Accounts for state.
*/
ssize_t SCTPServer::send_raw(std::shared_ptr<IClient>& c, const void* buf, size_t len) {
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
		if (SSL_ERROR_NONE != SSL_get_error(c->ssl, written)) throw std::runtime_error("SSL_write");

		assert(BIO_ctrl_pending(c->output_bio));

		char outbuf[BUFFER_SIZE] = { 0 };
		int read = BIO_read(c->output_bio, outbuf, sizeof(outbuf));
		if (SSL_ERROR_NONE != SSL_get_error(c->ssl, read)) throw std::runtime_error("BIO_read");

		sent = usrsctp_sendv(c->sock, outbuf, read,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
	}

	if (sent < 0) throw std::runtime_error(std::string("usrsctp_sendv: ") + strerror(errno));

	return sent;
}


/*
	Accepting new connections with blocking sctp accept.
	Runs in own thread
*/
void SCTPServer::accept_loop() {
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

				//clients_.push_back(std::make_shared<Client>(conn_sock, *this));
				clients_.push_back(cfg_->client_factory(conn_sock, *this));
				try {
					clients_.back()->init();
					clients_.back()->set_state(Client::SCTP_ACCEPTED);
				} catch (const std::runtime_error& exc) {
					ERROR(std::string("Dropping client: ") + exc.what());
					clients_.back()->set_state(Client::PURGE);
					drop_client(clients_.back());
				}
			}
		}
	/* at this point accept loop has ended
		but there still could be client to serve */
	} catch (const std::runtime_error& exc) {
		CRITICAL(std::string("Not accepting new clients anymore: ") + exc.what());
	}

	TRACE_func_left();
}


void SCTPServer::drop_client(std::shared_ptr<IClient>& c) {
	std::lock_guard<std::mutex> lock(clients_mutex_);
	clients_.erase(std::remove_if(clients_.begin(), clients_.end(),
	 [&] (auto s_ptr) { return s_ptr->sock == c->sock;}), clients_.end());
}


static void _log_client_error_and_throw(const char* func, std::shared_ptr<IClient>& c,
													 bool should_throw) {
	std::shared_ptr<SCTPServer::Config> cfg_ = c->server_.cfg_;

	std::string error { func };
	error += ": ";
	error += c->to_string();
	error += " ";
	error += strerror(errno);
	ERROR(error);
	if (should_throw) throw std::runtime_error(error);
}

static void log_client_error(const char* func, std::shared_ptr<IClient>& c) {
	_log_client_error_and_throw(func, c, false);
}

static void log_client_error_and_throw(const char* func, std::shared_ptr<IClient>& c) {
	_log_client_error_and_throw(func, c, true);
}


/*
	handle_upcall is called by usrsctp engine on any (configurable ?) *client* socket event,
	such as : data, successeful connect, client shutdown etc
	handle_upcall is registered with any new client socket in accept thread
*/
void SCTPServer::handle_upcall(struct socket* sock, void* arg, int) {
	#define BUFFERSIZE (1<<16)

	SCTPServer* s = (SCTPServer*) arg; assert(s);
	std::shared_ptr<SCTPServer::Config> cfg_ = ((SCTPServer*) arg)->cfg_;
	
	TRACE_func_entry();

	auto& clients = s->clients_;

	std::shared_ptr<IClient> c;
	{
		std::lock_guard<std::mutex> lock(s->clients_mutex_);

		auto it = find_if(clients.cbegin(), clients.cend(), [&] (auto s_ptr) {
			return s_ptr->sock == sock;
		});

		if (it != clients.cend()) {
			c = *it;
		} else {
			throw std::runtime_error("handle_upcall: client socket not found ?");
		}
	}
	
	int events = usrsctp_get_events(sock);

	if ((events & SCTP_EVENT_WRITE) && c->state < Client::SCTP_CONNECTED) {
		DEBUG(std::string("SCTP_EVENT_WRITE for: ") + (*c).to_string());
		try {
			c->set_state(Client::SCTP_CONNECTED);
		} catch (const std::runtime_error& exc) {
			ERROR(std::string("Dropping client: ") + exc.what());
			c->set_state(Client::PURGE);
			s->drop_client(c);
		}
	}

	if (events & SCTP_EVENT_READ && c->state >= Client::SCTP_CONNECTED) {
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

		n = usrsctp_recvv(sock, buf, BUFFERSIZE, (struct sockaddr*) &addr, &from_len, (void *) &rn,
								&infolen, &infotype, &flags);
		/* got data */
		if (n > 0) {
			if (flags & MSG_NOTIFICATION) {
				printf("Notification of length %llu received.\n", (unsigned long long) n);
			} else {
				try {
					c->server_.handle_client_data(c, buf, n, addr, rn, infotype, flags);
				} catch (const std::runtime_error& exc) {
					log_client_error("handle_client_data", c);
				}
			}
		/* client disconnected */
		} else if (n == 0) {
			INFO(c->to_string() + std::string(" disconnected."));
			c->set_state(Client::PURGE);
			s->drop_client(c);
		/* client disconnected */
		} else { // wtf ?
			free(buf);
			log_client_error("usrsctp_recvv", c);
		}

		free(buf);
		// //events = usrsctp_get_events(sock);
	}


	TRACE_func_left();

	return;
}




#if 0
void SCTPServer::client_loop(std::shared_ptr<SCTPClient> client) {
	#define BUFFER_SIZE 10240 // ?

	TRACE_func_entry();
	// Thread id std::this_thread::get_id();

	unsigned int infotype;
	struct sctp_rcvinfo rcv_info;
	struct sockaddr_in addr;
	socklen_t from_len;
	ssize_t n;
	int flags;
	socklen_t infolen;
	char buffer[BUFFER_SIZE];

	while (1) {
		from_len = (socklen_t) sizeof(struct sockaddr_in);
		flags = 0;
		infolen = (socklen_t) sizeof(struct sctp_rcvinfo);
		n = usrsctp_recvv(client->client_sock, (void*)buffer, BUFFER_SIZE, (struct sockaddr *) &addr, &from_len, (void *)&rcv_info,
		                  &infolen, &infotype, &flags);
		if (n > 0) {
			if (flags & MSG_NOTIFICATION) {
				printf("Notification of length %llu received.\n", (unsigned long long) n);
			} else {
				handle_client_data(client, buffer, n, addr, rcv_info, infotype, flags);
			}
		} else {
			debug("received n <= 0");
			break;
		}
	}

	//usrsctp_shutdown(client->client_sock, SHUT_RDWR); // (?) check for 0 = ok, -1 = fail
	//usrsctp_close(client->client_sock);
	//client->state = SCTPClient::PURGE;

	TRACE_func_entry();
}
#endif



void SCTPServer::handle_client_data(std::shared_ptr<IClient>& c, const void* buffer, ssize_t n, 
						const struct sockaddr_in& addr, const struct sctp_recvv_rn& rcv_info,
						unsigned int infotype, int flags) {

	DEBUG(std::string("handle_client_data: ") + c->to_string());

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
						DEBUG("output BIO_ctrl_pending");

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
								"Msg %s of length %llu received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u, complete %d.\n",
								(char*) outbuf,
								(unsigned long long) read,
								inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN), ntohs(addr.sin_port),
								rcv_info.recvv_rcvinfo.rcv_sid,	rcv_info.recvv_rcvinfo.rcv_ssn,	rcv_info.recvv_rcvinfo.rcv_tsn,
								ntohl(rcv_info.recvv_rcvinfo.rcv_ppid), rcv_info.recvv_rcvinfo.rcv_context,
								(flags & MSG_EOR) ? 1 : 0);
				} else {
					snprintf(message, sizeof message, "Msg %s of length %llu received from %s:%u, complete %d.\n",
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


/* testing "seams". C lib function wrappers */
inline struct socket* SCTPServer::usrsctp_socket(int domain, int type, int protocol,
               int (*receive_cb)(struct socket *sock, union sctp_sockstore addr, void *data,
                                 size_t datalen, struct sctp_rcvinfo, int flags, void *ulp_info),
               int (*send_cb)(struct socket *sock, uint32_t sb_free),
               uint32_t sb_threshold, void *ulp_info) {
	return ::usrsctp_socket(domain, type, protocol,receive_cb, send_cb, sb_threshold, ulp_info);
};


std::ostream& operator<<(std::ostream& out, const SCTPServer::Config& c) {
	out << "UDP encaps port: " << std::to_string(c.udp_encaps_port) << ", ";
	out << "SCTP port: " << std::to_string(c.sctp_port) << ", ";	
	out << "Data callback: " << (c.data_cback_f == nullptr ? "nullptr" : "set") << ", ";
	out << "Debug callback: " << (c.debug_f == nullptr ? "nullptr" : "set") << ", ";
	out << "SSL certificate: " << c.cert_filename << ", ";
	out << "SSL key: " << c.key_filename;	
	return out;
}

std::ostream& operator<<(std::ostream &out, const SCTPServer &s) {
	out << *(s.cfg_);
	return out;
}
