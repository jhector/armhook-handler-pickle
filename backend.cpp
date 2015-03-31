#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "backend.h"

int rand_fd;

void write_log(const char *msg, uint32_t size)
{
	int fd = fileno(stdout);
	write(fd, msg, size);
}

bool blacklisted(const char *name)
{
#if 0
	if (strstr(name, "Constructor"))
		return true;
#endif

	return false;
}

bool log_enabled(const char *name)
{
	char *filter = getenv("HOOK_LOG_MSG");

	if (!filter || !strstr(name, filter))
		return false;

	return true;
}

void log_message(const char *name, const char *msg)
{
	char buffer[256] = {0};

	snprintf(buffer, sizeof(buffer), "name: %s, msg: %s\n", name, msg);

	write_log(buffer, strlen(buffer));
}

void dump_hex(uint8_t *data, int len)
{
	char readable[17] = {0};

	for (int i=0; i<len; i++) {
		if (!(i % 16)) {
			if (i != 0)
				printf("  %s\n", readable);

			printf(" %08x ", i);
		}

		printf(" %02x", data[i]);

		if ((data[i] > 0x19) && (data[i] < 0x7f))
			readable[i % 16] = data[i];
		else
			readable[i % 16] = '.';

		readable[(i % 16)+1] = 0x0;
	}

	int padding = 0;
	if ((padding = (len % 16))) {
		for (int i=0; i<(16-padding); i++)
			printf("   ");
	}

	printf("  %s\n", readable);
}

void log_fuzzed(const char *name, int offset, uint8_t *old, int old_size,
	uint8_t *rep, int rep_size)
{
	char buf[256] = {0};

	snprintf(buf, sizeof(buf), "name: %s\noffset: 0x%08x\n", name, offset);

	write_log("======\n", 7);
	write_log(buf, strlen(buf));
	write_log("original:\n", 10);
	dump_hex(old, old_size);

	write_log("\n", 1);
	write_log("replaced:\n", 10);
	dump_hex(rep, rep_size);

	write_log("\n", 1);
}

bool msg_enabled(const char *name)
{
	char *filter = getenv("HOOK_FUZZ_MSG");
	if (!filter || !strstr(name, filter))
		return false;

	return true;
}

static int open_random()
{
	if (rand_fd > 0 || (rand_fd = open("/dev/urandom", O_RDONLY)) > 0)
		return rand_fd;

	return -1;
}

static void get_random(void *out, int length)
{
	int fd = open_random(), i = 0;
	if (fd < 0) {
		for (i=0; i<length; i++)
			((char*)out)[i] = 0x41;
	} else {
		read(fd, out, length);
	}
}

int16_t get_int16()
{
	int16_t value;
	get_random(&value, sizeof(value));

	return value;
}

int get_int()
{
	int value;
	get_random(&value, sizeof(value));

	return value;
}

bool get_bool()
{
	int value = get_int();

	return (value % 2) ? true : false;
}

long get_long()
{
	long value;
	get_random(&value, sizeof(value));

	return value;
}

int get_length()
{
	return get_int() & 0xfff;
}

int64_t get_int64()
{
	int64_t value = 0;
	get_random(&value, sizeof(value));

	return value;
}

char *get_bytes(int length)
{
	char buf[length];
	get_random(buf, length);

	return buf;
}

char *get_data(int *length)
{
	*length = get_length();
	return get_bytes(*length);
}

void get_string(std::string *out)
{
	int length = get_length();
	char *bytes = get_bytes(length);

	out->assign(bytes, length);
}

bool int16_enabled() { return (getenv("HOOK_FUZZ_INT16") ? true : false); }
bool int_enabled() { return (getenv("HOOK_FUZZ_INT") ? true : false); }
bool bool_enabled() { return (getenv("HOOK_FUZZ_BOOL") ? true : false); }
bool long_enabled() { return (getenv("HOOK_FUZZ_LONG") ? true : false); }
bool length_enabled() { return (getenv("HOOK_FUZZ_LENGTH") ? true : false); }
bool int64_enabled() { return (getenv("HOOK_FUZZ_INT64") ? true : false); }
bool bytes_enabled() { return (getenv("HOOK_FUZZ_BYTES") ? true : false); }
bool data_enabled() { return (getenv("HOOK_FUZZ_DATA") ? true : false); }
bool string_enabled() { return (getenv("HOOK_FUZZ_STRING") ? true : false); }
