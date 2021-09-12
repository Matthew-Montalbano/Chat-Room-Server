#include <string.h>
#include <stdlib.h>

#include "user.h"
#include "debug.h"
#include "csapp.h"

struct user {
	char *handle;
	int ref_count;
	sem_t ref_mutex;
};


USER *user_create(char *handle) {
	char *private_handle = malloc(strlen(handle) + 1);
	if (private_handle == NULL) return NULL;
	strcpy(private_handle, handle);
	USER *user = malloc(sizeof(USER));
	if (user == NULL) {
		free(private_handle);
		return NULL;
	}
	user->handle = private_handle;
	user->ref_count = 1;
	Sem_init(&user->ref_mutex, 0, 1);
	return user;
}

USER *user_ref(USER *user, char *why) {
	P(&user->ref_mutex);
	user->ref_count += 1;
	debug("Increasing @%s's reference count (%d -> %d) %s", user->handle, user->ref_count - 1, user->ref_count, why);
	V(&user->ref_mutex);
	return user;
}

void user_unref(USER *user, char *why) {
	P(&user->ref_mutex);
	user->ref_count -= 1;
	debug("Decreasing @%s's reference count (%d -> %d) %s", user->handle, user->ref_count + 1, user->ref_count, why);
	if (user->ref_count == 0) {
		free(user->handle);
		free(user);
		return;
	}
	V(&user->ref_mutex);
}

char *user_get_handle(USER *user) {
	return user->handle;
}