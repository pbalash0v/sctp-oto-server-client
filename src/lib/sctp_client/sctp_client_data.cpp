#include <memory>
#include <cstring>

#include "sctp_client.h"


SCTPClient::Data::Data() : size(0), buf(nullptr) {};


SCTPClient::Data::Data(const void* from, size_t len)
{
	buf = calloc(len, sizeof(char));
	if (not buf) throw std::runtime_error("Calloc failed.");

	memcpy(buf, from, len);
	size = len;
}


SCTPClient::Data::Data(Data&& other): size(0), buf(nullptr)
{
	size = other.size;
	buf = other.buf;

	other.size = 0;
	other.buf = nullptr;
}


SCTPClient::Data& SCTPClient::Data::operator=(SCTPClient::Data&& other)
{
	if (this != &other) {
		// release the current object's resources
		std::free(buf);
		size = 0;

		// other's resource
		size = other.size;
		buf = other.buf;

		// reset other
		other.size = 0;
		other.buf = nullptr;
	}

	return *this;
}


SCTPClient::Data::~Data()
{
	std::free(buf);
}

