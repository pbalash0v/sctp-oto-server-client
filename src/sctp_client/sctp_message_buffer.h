#include <memory>
#include <cstring>

namespace sctp {

	struct MessageBuffer {
		MessageBuffer(size_t);
		MessageBuffer(const MessageBuffer& oth) = delete;
		MessageBuffer& operator=(const MessageBuffer& oth) = delete;
		virtual ~MessageBuffer() {};

		void* operator()();

		void realloc_buffer();
		void reset_buffer();

		void* get_writable_buffer() const;
		void* get_message_buffer() const;

		size_t get_writable_buffer_size() const noexcept;
		size_t get_buffered_data_size() const noexcept;

		size_t message_size = { 0 };
		size_t buffered_data_size { 0 };
		size_t available_buffer_space { 0 };
		bool buffer_needs_realloc { false };

		std::unique_ptr<void, decltype(&std::free)> buff {nullptr, std::free};
		size_t size { 0 };
	};

}