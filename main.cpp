#include <string>

#include "message.h"
#include "hook.h"

extern "C" {
int8_t pickle_ReadString(struct hook_data *h_data);
}

static int8_t ReadString(struct hook_data *h_data)
{
	IPCMessage *obj = (IPCMessage*)h_data->r0;
	void **iter = (void**)h_data->r1;
	std::string *result = (std::string*)h_data->r2;

	return 0;
}

/*
 * data->r0 = IPCMessage *this
 * data->r1 = void **iter
 * data->r2 = std::string *result
 */
int8_t pickle_ReadString(struct hook_data *h_data)
{
	return ReadString(h_data);
}
