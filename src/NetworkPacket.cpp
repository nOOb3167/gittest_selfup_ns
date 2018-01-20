#include <cassert>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

#include <selfup/NetworkPacket.h>

NetworkPacket::NetworkPacket(uint8_t *data, size_t data_len, networkpacket_buf_len_tag_t) :
	m_data(data, data + data_len),
	m_off(0)
{
	m_data.reserve(VSERV_NETWORKPACKET_SIZE_INCREMENT);
}

NetworkPacket::NetworkPacket(uint8_t cmd, networkpacket_cmd_tag_t) :
	m_data(),
	m_off(0)
{
	(*this) << cmd;
}

NetworkPacket NetworkPacket::copyReset()
{
	NetworkPacket packet(m_data.data(), m_data.size(), networkpacket_buf_len_tag_t());
	packet.m_off = 0;
	return packet;
}

uint8_t * NetworkPacket::getDataPtr()
{
	return m_data.data();
}

size_t NetworkPacket::getDataSize()
{
	return m_data.size();
}

size_t NetworkPacket::getRemainingSize()
{
	assert(m_data.size() >= m_off);
	return m_data.size() - m_off;
}

const char * NetworkPacket::inSizedStr(size_t len)
{
	checkReadOffset(m_off, len);
	const char *p = (const char *)(m_data.data() + m_off);
	m_off += len;
	return p;
}

void NetworkPacket::outSizedStr(const char *str, size_t len)
{
	checkDataSize(len);
	memcpy(m_data.data() + m_off, str, len);
	m_off += len;
}

void NetworkPacket::rewriteU16At(size_t off, uint16_t i, uint16_t *opt_old_val)
{
	if (getDataSize() < off + 2)
		throw std::runtime_error("packet data size at");
	if (opt_old_val)
		assert(*opt_old_val == ((m_data[off + 0] << 8) | (m_data[off + 1] << 0)));
	m_data[off + 0] = (i >> 8) & 0xFF;
	m_data[off + 1] = (i >> 0) & 0xFF;
}

uint8_t NetworkPacket::readU8(const uint8_t *data)
{
	return (data[0] << 0);
}

void NetworkPacket::writeU8(uint8_t *data, uint8_t i)
{
	data[0] = (i >> 0) & 0xFF;
}

uint16_t NetworkPacket::readU16(const uint8_t *data)
{
	return
		(data[0] << 8) | (data[1] << 0);
}

void NetworkPacket::writeU16(uint8_t *data, uint16_t i)
{
	data[0] = (i >> 8) & 0xFF;
	data[1] = (i >> 0) & 0xFF;
}

uint32_t NetworkPacket::readU32(const uint8_t *data)
{
	return
		(data[0] << 24) | (data[1] << 16) | (data[2] << 8) | (data[3] << 0);
}

void NetworkPacket::writeU32(uint8_t *data, uint32_t i)
{
	data[0] = (i >> 24) & 0xFF;
	data[1] = (i >> 16) & 0xFF;
	data[2] = (i >> 8) & 0xFF;
	data[3] = (i >> 0) & 0xFF;
}

void NetworkPacket::checkReadOffset(uint32_t from_offset, uint32_t field_size)
{
	if (from_offset + field_size > m_data.size())
		throw std::runtime_error("packet data size");
}

void NetworkPacket::checkDataSize(uint32_t field_size)
{
	if (m_off + field_size > m_data.capacity())
		m_data.reserve(m_data.capacity() + VSERV_NETWORKPACKET_SIZE_INCREMENT);
	if (m_off + field_size > m_data.size())
		m_data.resize(m_data.size() + field_size);
}

NetworkPacket& NetworkPacket::operator>>(uint8_t& dst)
{
	checkReadOffset(m_off, 1);
	dst = readU8(m_data.data() + m_off);
	m_off += 1;
	return *this;
}

NetworkPacket& NetworkPacket::operator<<(uint8_t src)
{
	checkDataSize(1);
	writeU8(m_data.data() + m_off, src);
	m_off += 1;
	return *this;
}

NetworkPacket& NetworkPacket::operator>>(uint16_t& dst)
{
	checkReadOffset(m_off, 2);
	dst = readU16(m_data.data() + m_off);
	m_off += 2;
	return *this;
}

NetworkPacket& NetworkPacket::operator<<(uint16_t src)
{
	checkDataSize(2);
	writeU16(m_data.data() + m_off, src);
	m_off += 2;
	return *this;
}

NetworkPacket& NetworkPacket::operator>>(uint32_t& dst)
{
	checkReadOffset(m_off, 4);
	dst = readU32(m_data.data() + m_off);
	m_off += 4;
	return *this;
}

NetworkPacket& NetworkPacket::operator<<(uint32_t src)
{
	checkDataSize(4);
	writeU32(m_data.data() + m_off, src);
	m_off += 4;
	return *this;
}
