#include <iostream>
#include <cstring>
#include <stdexcept>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "rand_data_gen.hpp"

RandGen::RandGen()
{
	urandom_fd_ = open("/dev/urandom", O_RDONLY);
	if (urandom_fd_ < 0) {
		throw std::runtime_error(strerror(errno));
	}
}


RandGen::~RandGen()
{
	int res = close(urandom_fd_);
	if (res < 0) {
		std::cerr << strerror(errno);
	}	
}

std::vector<char> RandGen::operator()()
{
	std::vector<char> v;

	uint16_t val = 0;

	// get random data size -> 1..65535
	while (true) {
		char buf[2] = { 0 };

		int num_read = read(urandom_fd_, buf, sizeof buf);
		if (num_read < 0) {
			throw std::runtime_error(strerror(errno));
		}

		val = buf[0];
		val <<= 8;
		val |= buf[1];

		if (val != 0) break;
	}

	//actually read as much random data
	v.resize(val);

	int num_read = read(urandom_fd_, v.data(), val);
	if (num_read < 0) {
		throw std::runtime_error(strerror(errno));
	}
	if (num_read != val) {
		throw std::runtime_error("short read.");
	}

	return v;
}

