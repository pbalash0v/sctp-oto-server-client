#include <memory>
#include <cstring>

#include "sctp_message_buffer.h"

using namespace sctp;

MessageBuffer::MessageBuffer(size_t len) 
	: message_size(len), available_buffer_space(len)
{
	buff = ([&]()
	{
		void* buf_ = calloc(len, sizeof(char));
		if (not buf_) throw std::runtime_error("Calloc in ctor failed.");
		return std::unique_ptr<void, decltype(&std::free)> (buf_, std::free);
	})();
}

void* MessageBuffer::get_writable_buffer() const
{
	return static_cast<char*>(buff.get()) + get_buffered_data_size();
}

void* MessageBuffer::operator()()
{
	return buff.get();
}

void* MessageBuffer::get_message_buffer() const
{
	return buff.get();
}

void MessageBuffer::realloc_buffer()
{
	void* new_buff = realloc(buff.get(), available_buffer_space + message_size);
	if (new_buff) {
		available_buffer_space += message_size;
		if (new_buff != buff.get()) {
			buff.release();
			buff.reset(new_buff);
		}
		buffered_data_size += message_size;
		//memset(get_writable_buffer(), 0, CLIENT_BUFFERSIZE);
		buffer_needs_realloc = true;
	} else {
		throw std::runtime_error("Realloc in realloc_buffer() failed.");
	}

}

void MessageBuffer::reset_buffer()
{
	if (buffer_needs_realloc) {
		void* new_buff = realloc(buff.get(), message_size);

		if (not new_buff) {
			throw std::runtime_error("Realloc in reset_buffer() failed.");
		}

		if (new_buff != buff.get()) buff.reset(new_buff);
	}

	memset(buff.get(), 0, message_size);
	available_buffer_space = message_size;
	buffered_data_size = 0;
	buffer_needs_realloc = false;
}



size_t MessageBuffer::get_buffered_data_size() const noexcept
{
	return buffered_data_size;
}
	

size_t MessageBuffer::get_writable_buffer_size() const noexcept
{
	return message_size;
}




