#pragma once


namespace sctp
{

struct Data final
{
	Data() = default;
	explicit Data(const void*, size_t);

	Data(const Data& oth) = delete;
	Data& operator=(const Data& oth) = delete;
	Data(Data&& other);
	Data& operator=(Data&& other);

	~Data();

	size_t size {};
	void* buf {nullptr};
};

}