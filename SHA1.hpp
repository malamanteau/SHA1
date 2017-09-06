#pragma once

#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iomanip>

class SHA1
{
public:
	SHA1();
	
	void Accumulate(uint8_t block);
	void Accumulate(uint16_t block);
	void Accumulate(uint32_t block);
	void Accumulate(uint64_t block);
	void Accumulate(std::string s);
	void Accumulate(char const * data, size_t sz);
	void Accumulate(uint8_t const * data, size_t sz);
	void AccumulateDateTime();

	std::string String128();           // Truncated 128 bits
	std::string String128Hyphenated(); // Truncated 128 bits
	std::string String160();           // Full      160 bits

	std::array<uint32_t, 5> ArrayU32x5(); // Full      160 bits
	std::array<uint32_t, 4> ArrayU32x4(); // Truncated 128 bits

	// SAVE in case we want these in the future!
	//std::array<uint32_t, 4> ArrayU64x2();                      // Truncated 128 bits
	//std::tuple<uint64_t, uint64_t>           Tuple64x2();      // Truncated 128 bits
	//std::tuple<uint64_t, uint64_t, uint32_t> Tuple64x2_32x1(); // Full      160 bits

	//static SHA1 NewUUID();

private:
	inline constexpr static uint64_t  arbitraryNumber() { return 0xA1DE7A1DE7A1DE70; } // "AIDEN AIDEN AIDEN 0" Should be arbitrary...
	inline constexpr static bool      isBigEndian()     { return false; } // TODO: Implement this someday when we actually care about ARM and/or Sun-Solaris.

	//static std::atomic_uint64_t s_counter;

	void                        transformAcc();
	std::array<uint32_t, 5>     currentHash();
	uint32_t                    rotl(uint32_t value, uint32_t shift) const;

	std::vector<uint8_t>        m_accumulator; // Never larger than 512 bytes.
	std::array<uint32_t, 5>     m_accHash = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
};

inline
SHA1::SHA1()
	: //m_accHash(), initialized inline!
	  m_accumulator()
{
	m_accumulator.reserve(512);
}

inline uint32_t 
SHA1::rotl(uint32_t value, uint32_t shift) const
{
	return ((value << shift) | (value >> (32 - shift)));
}

inline void
SHA1::transformAcc()
{
	uint8_t * block_ = &m_accumulator[0];

	uint32_t f;
	std::array<uint32_t, 5> h = m_accHash;
	std::array<uint32_t, 80> word;

	for (int i = 0; i < 16; ++i)
		word[i] = 
		(block_[i * 4 + 0] << 24) | 
		(block_[i * 4 + 1] << 16) | 
		(block_[i * 4 + 2] <<  8) | 
		(block_[i * 4 + 3] <<  0);

	for (int i = 16; i < 80; ++i)
		word[i] = rotl((
			word[i -  3] ^ 
			word[i -  8] ^ 
			word[i - 14] ^ 
			word[i - 16]), 1);

	for (int run = 0; run < 80; ++run) 
	{
		if (run <= 19)
			f = ((h[1] & h[2]) | ((~h[1]) & h[3])) + 0x5a827999;
		else if (run <= 39)
			f = (h[1] ^ h[2] ^ h[3]) + 0x6ed9eba1;
		else if (run <= 59)
			f = ((h[1] & h[2]) | (h[1] & h[3]) | (h[2] & h[3])) + 0x8f1bbcdc;
		else
			f = (h[1] ^ h[2] ^ h[3]) + 0xca62c1d6;

		f += rotl(h[0], 5) + h[4] + word[run];
		h[4] = h[3];
		h[3] = h[2];
		h[2] = rotl(h[1], 30);
		h[1] = h[0];
		h[0] = f;
	}

	for (uint32_t i = 0; i < m_accHash.size(); ++i)
		m_accHash[i] += h[i];
}

inline void
SHA1::Accumulate(uint8_t block)
{
	m_accumulator.push_back(block);

	if (m_accumulator.size() == 512)
	{
		transformAcc();
		m_accumulator.clear();
	}
}

inline void
SHA1::Accumulate(uint16_t block)
{
	if (isBigEndian())
	{
		Accumulate(uint8_t((block & 0xFF00) >> 4));
		Accumulate(uint8_t( block & 0x00FF));
	}
	else
	{
		Accumulate(uint8_t( block & 0x00FF));
		Accumulate(uint8_t((block & 0xFF00) >> 4));
	}
}

inline void
SHA1::Accumulate(uint32_t block)
{
	if (isBigEndian())
	{
		Accumulate(uint8_t((block & 0xFF000000) >> 12));
		Accumulate(uint8_t((block & 0x00FF0000) >> 8));
		Accumulate(uint8_t((block & 0x0000FF00) >> 4));
		Accumulate(uint8_t( block & 0x000000FF));
	}
	else
	{
		Accumulate(uint8_t( block & 0x000000FF));
		Accumulate(uint8_t((block & 0x0000FF00) >> 4));
		Accumulate(uint8_t((block & 0x00FF0000) >> 8));
		Accumulate(uint8_t((block & 0xFF000000) >> 12));
	}
}

inline void
SHA1::Accumulate(uint64_t block)
{
	if (isBigEndian())
	{
		Accumulate(uint8_t((block & 0xFF00000000000000) >> 28));
		Accumulate(uint8_t((block & 0x00FF000000000000) >> 24));
		Accumulate(uint8_t((block & 0x0000FF0000000000) >> 20));
		Accumulate(uint8_t((block & 0x000000FF00000000) >> 16));
		Accumulate(uint8_t((block & 0x00000000FF000000) >> 12));
		Accumulate(uint8_t((block & 0x0000000000FF0000) >>  8));
		Accumulate(uint8_t((block & 0x000000000000FF00) >>  4));
		Accumulate(uint8_t( block & 0x00000000000000FF));
	}
	else
	{
		Accumulate(uint8_t( block & 0x00000000000000FF));
		Accumulate(uint8_t((block & 0x000000000000FF00) >>  4));
		Accumulate(uint8_t((block & 0x0000000000FF0000) >>  8));
		Accumulate(uint8_t((block & 0x00000000FF000000) >> 12));
		Accumulate(uint8_t((block & 0x000000FF00000000) >> 16));
		Accumulate(uint8_t((block & 0x0000FF0000000000) >> 20));
		Accumulate(uint8_t((block & 0x00FF000000000000) >> 24));
		Accumulate(uint8_t((block & 0xFF00000000000000) >> 28));
	}
}

inline void
SHA1::Accumulate(std::string s)
{
	Accumulate(s.data(), s.size());
}

inline void
SHA1::Accumulate(char const * data, size_t sz)
{
	for (size_t s = 0; s < sz; s++)
		Accumulate(reinterpret_cast<uint8_t const *>(data)[s]);
}

inline void
SHA1::Accumulate(uint8_t const * data, size_t sz)
{
	for (size_t s = 0; s < sz; s++)
		Accumulate(data[s]);
}


inline std::array<uint32_t, 5> 
SHA1::currentHash()
{
	size_t sz = m_accumulator.size();

	if (sz > 0)
	{
		std::array<uint32_t, 5> temp = m_accHash;

		m_accumulator.resize(512, 0_u8);
		{
			transformAcc();
			std::swap(temp, m_accHash);
		}
		m_accumulator.resize(sz);

		return temp;
	}

	return m_accHash;
}

inline void
SHA1::AccumulateDateTime()
{
	auto dti = std::chrono::high_resolution_clock::now().time_since_epoch().count();
	Accumulate(reinterpret_cast<uint8_t *>(&dti), (size_t) sizeof(dti));
}

inline std::string 
SHA1::String128()
{
	std::array<uint32_t, 5> temp = currentHash();
	std::array<uint32_t, 4> hashTable = { temp[0], temp[1], temp[2], temp[3] };

	std::ostringstream oss;

	for (auto & hash : hashTable) 
		oss << std::hex << std::setfill('0') << std::setw(8) << hash;

	return oss.str();
}

// Format: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
inline std::string 
SHA1::String128Hyphenated()
{
	std::array<uint32_t, 5> temp = currentHash();
	std::array<uint32_t, 4> hashTable = { temp[0], temp[1], temp[2], temp[3] };

	std::ostringstream oss;

	for (auto & hash : hashTable) 
		oss << std::hex << std::setfill('0') << std::setw(8) << hash;

	std::string ret = oss.str();

	ret.insert(20, std::string("-"));
	ret.insert(16, std::string("-"));
	ret.insert(12, std::string("-"));
	ret.insert(8, std::string("-"));

	return ret;
}

inline std::string 
SHA1::String160()
{
	std::array<uint32_t, 5> hashTable = currentHash();

	std::ostringstream oss;

	for (auto & hash : hashTable) 
		oss << std::hex << std::setfill('0') << std::setw(8) << hash;

	return oss.str();
}

inline std::array<uint32_t, 5> 
SHA1::ArrayU32x5()
{
	return currentHash();
}

inline std::array<uint32_t, 4> 
SHA1::ArrayU32x4()
{
	std::array<uint32_t, 5> hashTable = currentHash();
	return { hashTable[0], hashTable[1], hashTable[2], hashTable[3] };
}

//inline std::array<uint32_t, 4> 
//SHA1::ArrayU64x2()
//{
//	std::array<uint32_t, 5> hashTable = finishHash();
//	return {
//		(((uint64_t)hashTable[0]) << 64) & (uint64_t)hashTable[1], 
//		(((uint64_t)hashTable[2]) << 64) & (uint64_t)hashTable[3] };
//}

//inline SHA1 
//SHA1::NewUUID()
//{
//	SHA1 ret{};
//
//	ret.AccumulateDateTime();
//	//ret.Accumulate(++s_counter);
//	ret.Accumulate(arbitraryNumber());
//
//	return ret;
//}