#ifndef HANDLER_BACKEND_H_
#define HANDLER_BACKEND_H_

#include <stdint.h>

#include <string>

bool blacklisted(const char *name);

bool log_enabled(const char *name);
void log_message(const char *name, const char *msg);

void log_fuzzed(const char *name, int offset, uint8_t *old, int old_size,
	uint8_t *rep, int rep_size);

bool msg_enabled(const char *name);

bool int16_enabled();
int16_t get_int16();

bool int_enabled();
int get_int();

bool bool_enabled();
bool get_bool();

bool long_enabled();
long get_long();

bool length_enabled();
int get_length();

bool int64_enabled();
int64_t get_int64();

bool bytes_enabled();
char *get_bytes(int length);

bool data_enabled();
char *get_data(int *length);

bool string_enabled();
void get_string(std::string *out);

#endif /* HANDLER_BACKEND_H_ */
