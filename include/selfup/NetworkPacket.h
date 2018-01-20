#ifndef _NETWORK_PACKET_H_
#define _NETWORK_PACKET_H_

#include <cstdint>
#include <stdexcept>
#include <vector>

#define VSERV_NETWORKPACKET_SIZE_INCREMENT 4096

struct networkpacket_buf_len_tag_t {};
struct networkpacket_cmd_tag_t {};

class ProtocolExc : public std::runtime_error
{
public:
	ProtocolExc(const char *msg);
};

class NetworkPacket
{
public:
	NetworkPacket(uint8_t *data, size_t data_len, networkpacket_buf_len_tag_t);
	NetworkPacket(uint8_t cmd, networkpacket_cmd_tag_t);

	~NetworkPacket() = default;

	NetworkPacket(const NetworkPacket &a)            = delete;
	NetworkPacket& operator=(const NetworkPacket &a) = delete;
	NetworkPacket(NetworkPacket &&a)            = default;
	NetworkPacket& operator=(NetworkPacket &&a) = default;

	NetworkPacket copyReset();

	uint8_t * getDataPtr();
	size_t getDataSize();
	size_t getRemainingSize();

	uint8_t readU8(const uint8_t *data);
	void writeU8(uint8_t *data, uint8_t i);

	uint16_t readU16(const uint8_t *data);
	void writeU16(uint8_t *data, uint16_t i);

	uint32_t readU32(const uint8_t *data);
	void writeU32(uint8_t *data, uint32_t i);

	void checkReadOffset(uint32_t from_offset, uint32_t field_size);
	void checkDataSize(uint32_t field_size);

	const char * inSizedStr(size_t len);
	void outSizedStr(const char *str, size_t len);

	void rewriteU16At(size_t off, uint16_t i, uint16_t *opt_old_val);

	NetworkPacket& operator>>(uint8_t& dst);
	NetworkPacket& operator<<(uint8_t src);

	NetworkPacket& operator>>(uint16_t& dst);
	NetworkPacket& operator<<(uint16_t src);

	NetworkPacket& operator>>(uint32_t& dst);
	NetworkPacket& operator<<(uint32_t src);

private:
	std::vector<uint8_t> m_data;
	size_t m_off;
};

#endif /* _NETWORK_PACKET_H_ */
