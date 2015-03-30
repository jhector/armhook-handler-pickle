#include <string>

#include "backend.h"
#include "message.h"
#include "hook.h"

#define ALIGN_SIZE sizeof(uint32_t)

#define __ALIGN_MASK(x,mask) (((x)+(mask))&~(mask))
#define ALIGN(x) __ALIGN_MASK(x,ALIGN_SIZE-1)

extern "C" {
int8_t pickle_ReadInt16(struct hook_data *h_data);
int8_t pickle_ReadInt(struct hook_data *h_data);
int8_t pickle_ReadBool(struct hook_data *h_data);
int8_t pickle_ReadLong(struct hook_data *h_data);
int8_t pickle_ReadLength(struct hook_data *h_data);
int8_t pickle_ReadInt64(struct hook_data *h_data);
int8_t pickle_ReadBytes(struct hook_data *h_data);
int8_t pickle_ReadData(struct hook_data *h_data);
int8_t pickle_ReadString(struct hook_data *h_data);
}

static const char *payload(IPCMessage *obj)
{
	return reinterpret_cast<const char*>(obj->header_) + obj->header_size_;
}

static void UpdateIter(void **iter, int bytes)
{
	*iter = static_cast<char*>(*iter) + ALIGN(bytes);
}

static bool ReadInt16(IPCMessage *obj, void **iter, int16_t *result)
{
	if (!*iter)
		*iter = const_cast<char*>(payload(obj));

	memcpy(result, *iter, sizeof(*result));

	UpdateIter(iter, sizeof(*result));

	return true;
}

static bool ReadInt(IPCMessage *obj, void **iter, int *result)
{
	if (!*iter)
		*iter = const_cast<char*>(payload(obj));

	memcpy(result, *iter, sizeof(*result));

	UpdateIter(iter, sizeof(*result));

	return true;
}

static bool ReadBool(IPCMessage *obj, void **iter, bool *result)
{
	int tmp;
	if (!ReadInt(obj, iter, &tmp))
		return false;

	*result = tmp ? true : false;

	return true;
}

static bool ReadLong(IPCMessage *obj, void **iter, long *result)
{
	if (!*iter)
		*iter = const_cast<char*>(payload(obj));

	int64_t big_result = 0;
	memcpy(&big_result, *iter, sizeof(big_result));

	*result = static_cast<long>(big_result);

	UpdateIter(iter, sizeof(big_result));

	return true;
}

static bool ReadLength(IPCMessage *obj, void **iter, int *result)
{
	if (!ReadInt(obj, iter, result))
		return false;

	return ((*result) >= 0);
}

static bool ReadInt64(IPCMessage *obj, void **iter, int64_t *result)
{
	if (!*iter)
		*iter = const_cast<char*>(payload(obj));

	memcpy(result, *iter, sizeof(*result));

	UpdateIter(iter, sizeof(*result));

	return true;
}

static bool ReadBytes(IPCMessage *obj, void **iter, const char **data,
	int length, uint32_t alignment)
{
	if (!*iter)
		*iter = const_cast<char*>(payload(obj));

	uint32_t padding_len = intptr_t(*iter) % alignment;
	if (padding_len)
		length += padding_len;

	*data = static_cast<const char*>(*iter) + padding_len;

	UpdateIter(iter, length);

	return true;
}

static bool ReadData(IPCMessage *obj, void **iter, const char **data,
	int *length)
{
	if (!*iter)
		*iter = const_cast<char*>(payload(obj));

	if (!ReadLength(obj, iter, length))
		return false;

	return ReadBytes(obj, iter, data, *length, ALIGN_SIZE);
}

static bool ReadString(IPCMessage *obj, void **iter, std::string *result)
{
	if (!*iter)
		*iter = const_cast<char*>(payload(obj));

	int len;
	if (!ReadLength(obj, iter, &len))
		return false;

	char *chars = reinterpret_cast<char*>(*iter);
	result->assign(chars, len);

	UpdateIter(iter, len);

	return true;
}

static int get_offset(IPCMessage *obj, void **iter)
{
	if (!*iter)
		return 0;

	return (uint32_t)((uint32_t)(*iter) - (uint32_t)payload(obj));
}

/*
 * data->r0 = IPCMessage *this
 * data->r1 = void **iter
 * data->r2 = int16_t *result
 */
static int8_t ReadInt16(struct hook_data *h_data)
{
	IPCMessage *obj = (IPCMessage*)h_data->r0;
	void **iter = (void**)h_data->r1;
	int16_t *result = (int16_t*)h_data->r2;

	if (log_enabled(obj->name_))
		log_message(obj->name_, "ReadInt16");

	int offset = get_offset(obj, iter);
	h_data->r0 = (uint32_t)ReadInt16(obj, iter, result);

	if (int16_enabled() && !blacklisted(obj->name_) &&
		msg_enabled(obj->name_)) {
		int16_t old = *result;
		*result = get_int16();

		log_fuzzed(obj->name_, offset, (uint8_t*)&old, sizeof(old),
			(uint8_t*)result, sizeof(*result));
	}

	return 1;
}

/*
 * data->r0 = IPCMessage *this
 * data->r1 = void **iter
 * data->r2 = int *result
 */
static int8_t ReadInt(struct hook_data *h_data)
{
	IPCMessage *obj = (IPCMessage*)h_data->r0;
	void **iter = (void**)h_data->r1;
	int *result = (int*)h_data->r2;

	if (log_enabled(obj->name_))
		log_message(obj->name_, "ReadInt");

	int offset = get_offset(obj, iter);
	h_data->r0 = (uint32_t)ReadInt(obj, iter, result);

	if (int_enabled() && !blacklisted(obj->name_) &&
		msg_enabled(obj->name_)) {
		int old = *result;
		*result = get_int();

		log_fuzzed(obj->name_, offset, (uint8_t*)&old, sizeof(old),
			(uint8_t*)result, sizeof(*result));
	}

	return 1;
}

/*
 * data->r0 = IPCMessage *this
 * data->r1 = void **iter
 * data->r2 = bool *result
 */
static int8_t ReadBool(struct hook_data *h_data)
{
	IPCMessage *obj = (IPCMessage*)h_data->r0;
	void **iter = (void**)h_data->r1;
	bool *result = (bool*)h_data->r2;

	if (log_enabled(obj->name_))
		log_message(obj->name_, "ReadBool");

	int offset = get_offset(obj, iter);
	h_data->r0 = (uint32_t)ReadBool(obj, iter, result);

	if (bool_enabled() && !blacklisted(obj->name_) &&
		msg_enabled(obj->name_)) {
		bool old = *result;
		*result = get_bool();

		log_fuzzed(obj->name_, offset, (uint8_t*)&old, sizeof(old),
			(uint8_t*)result, sizeof(*result));
	}

	return 1;
}

/*
 * data->r0 = IPCMessage *this
 * data->r1 = void **iter
 * data->r2 = long *result
 */
static int8_t ReadLong(struct hook_data *h_data)
{
	IPCMessage *obj = (IPCMessage*)h_data->r0;
	void **iter = (void**)h_data->r1;
	long *result = (long*)h_data->r2;

	if (log_enabled(obj->name_))
		log_message(obj->name_, "ReadLong");

	int offset = get_offset(obj, iter);
	h_data->r0 = (uint32_t)ReadLong(obj, iter, result);

	if (long_enabled() && !blacklisted(obj->name_) &&
		msg_enabled(obj->name_)) {
		long old = *result;
		*result = get_long();

		log_fuzzed(obj->name_, offset, (uint8_t*)&old, sizeof(old),
			(uint8_t*)result, sizeof(*result));
	}

	return 1;
}

/*
 * data->r0 = IPCMessage *this
 * data->r1 = void **iter
 * data->r2 = int *result
 */
static int8_t ReadLength(struct hook_data *h_data)
{
	IPCMessage *obj = (IPCMessage*)h_data->r0;
	void **iter = (void**)h_data->r1;
	int *result = (int*)h_data->r2;

	if (log_enabled(obj->name_))
		log_message(obj->name_, "ReadLength");

	int offset = get_offset(obj, iter);
	h_data->r0 = (uint32_t)ReadLength(obj, iter, result);

	if (length_enabled() && !blacklisted(obj->name_) &&
		msg_enabled(obj->name_)) {
		int old = *result;
		*result = get_length();

		log_fuzzed(obj->name_, offset, (uint8_t*)&old, sizeof(old),
			(uint8_t*)result, sizeof(*result));
	}

	return 1;
}

/*
 * data->r0 = IPCMessage *this
 * data->r1 = void **iter
 * data->r2 = int64_t *result
 */
static int8_t ReadInt64(struct hook_data *h_data)
{
	IPCMessage *obj = (IPCMessage*)h_data->r0;
	void **iter = (void**)h_data->r1;
	int64_t *result = (int64_t*)h_data->r2;

	if (log_enabled(obj->name_))
		log_message(obj->name_, "ReadInt64");

	int offset = get_offset(obj, iter);
	h_data->r0 = (uint32_t)ReadInt64(obj, iter, result);

	if (int64_enabled() && !blacklisted(obj->name_) &&
		msg_enabled(obj->name_)) {
		int64_t old = *result;
		*result = get_int64();

		log_fuzzed(obj->name_, offset, (uint8_t*)&old, sizeof(old),
			(uint8_t*)result, sizeof(*result));
	}

	return 1;
}

/*
 * data->r0 = IPCMessage *this
 * data->r1 = void **iter
 * data->r2 = const char **data
 * data->r3 = int length
 * data->sp[0] = uint32_t alignment
 */
static int8_t ReadBytes(struct hook_data *h_data)
{
	IPCMessage *obj = (IPCMessage*)h_data->r0;
	void **iter = (void**)h_data->r1;
	const char **data = (const char**)h_data->r2;
	int length = (int)h_data->r3;
	uint32_t alignment = (uint32_t)h_data->sp[0];

	if (log_enabled(obj->name_))
		log_message(obj->name_, "ReadBytes");

	h_data->r0 = (uint32_t)ReadBytes(obj, iter, data, length, alignment);

	return 1;
}

/*
 * data->r0 = IPCMessage *this
 * data->r1 = void **iter
 * data->r2 = const char **data
 * data->r3 = int *length
 */
static int8_t ReadData(struct hook_data *h_data)
{
	IPCMessage *obj = (IPCMessage*)h_data->r0;
	void **iter = (void**)h_data->r1;
	const char **data = (const char**)h_data->r2;
	int *length = (int*)h_data->r3;

	if (log_enabled(obj->name_))
		log_message(obj->name_, "ReadData");

	h_data->r0 = (uint32_t)ReadData(obj, iter, data, length);

	return 1;
}

/*
 * data->r0 = IPCMessage *this
 * data->r1 = void **iter
 * data->r2 = int *result
 * data->r2 = std::string *result
 */
static int8_t ReadString(struct hook_data *h_data)
{
	IPCMessage *obj = (IPCMessage*)h_data->r0;
	void **iter = (void**)h_data->r1;
	std::string *result = (std::string*)h_data->r2;

	if (log_enabled(obj->name_))
		log_message(obj->name_, "ReadString");

	h_data->r0 = (uint32_t)ReadString(obj, iter, result);

	return 1;
}

int8_t pickle_ReadInt16(struct hook_data *h_data) { return ReadInt16(h_data); }
int8_t pickle_ReadInt(struct hook_data *h_data) { return ReadInt(h_data); }
int8_t pickle_ReadBool(struct hook_data *h_data) { return ReadBool(h_data); }
int8_t pickle_ReadLong(struct hook_data *h_data) { return ReadLong(h_data); }
int8_t pickle_ReadLength(struct hook_data *h_data) { return ReadLength(h_data); }
int8_t pickle_ReadInt64(struct hook_data *h_data) { return ReadInt64(h_data); }
int8_t pickle_ReadBytes(struct hook_data *h_data) { return ReadBytes(h_data); }
int8_t pickle_ReadData(struct hook_data *h_data) { return ReadData(h_data); }
int8_t pickle_ReadString(struct hook_data *h_data) { return ReadString(h_data); }
