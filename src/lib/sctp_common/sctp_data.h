#pragma once


namespace sctp
{

struct Data
{
	Data();
	explicit Data(const void*, size_t);
	Data(const Data& oth) = delete;
	Data& operator=(const Data& oth) = delete;
	Data(Data&& other);
	virtual ~Data();

	Data& operator=(Data&& other);

	size_t size { 0 };
	void* buf { nullptr };
};

}