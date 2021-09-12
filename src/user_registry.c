#include <string.h>

#include "user_registry.h"
#include "csapp.h"
#include "debug.h"

typedef struct handle_map_node {
	char *handle;
	USER *user;
	struct handle_map_node *next;
} handle_map_node;

struct user_registry {
	handle_map_node *head;
	sem_t registry_mutex;
};


handle_map_node *create_new_map_node(char *handle);



USER_REGISTRY *ureg_init(void) {
	USER_REGISTRY *registry = malloc(sizeof(USER_REGISTRY));
	if (registry == NULL) {
		return NULL;
	}
	registry->head = NULL;
	Sem_init(&registry->registry_mutex, 0, 1);
	debug("Initialize user registry");
	return registry;
}

void ureg_fini(USER_REGISTRY *ureg) {
	P(&ureg->registry_mutex);
	handle_map_node *node = ureg->head;
	handle_map_node *prev;
	while (node != NULL) {
		prev = node;
		node = node->next;
		user_unref(prev->user, "for cleaning up registry");
		free(prev);
	}
	V(&ureg->registry_mutex);
	free(ureg);
	debug("Finalize user registry");
}

USER *ureg_register(USER_REGISTRY *ureg, char *handle) {
	handle_map_node *prev, *new_node;
	P(&ureg->registry_mutex);
	handle_map_node *node = ureg->head;
	if (node == NULL) {
		if ((new_node = create_new_map_node(handle)) == NULL) {
			V(&ureg->registry_mutex);
			return NULL;
		}
		ureg->head = new_node;
		user_ref(new_node->user, "for being retrieved from the user registry");
		V(&ureg->registry_mutex);
		return new_node->user;
	}
	while (node != NULL) {
		if (strcmp(handle, node->handle) == 0) {
			user_ref(node->user, "for being retrieved from the user registry");
			V(&ureg->registry_mutex);
			return node->user;
		}
		prev = node;
		node = node->next;
	}
	if ((new_node = create_new_map_node(handle)) == NULL) {
		V(&ureg->registry_mutex);
		return NULL;
	}
	prev->next = new_node;
	user_ref(new_node->user, "for being retrieved from the user registry");
	V(&ureg->registry_mutex);
	return new_node->user;
}

handle_map_node *create_new_map_node(char *handle) {
	handle_map_node *new_node = malloc(sizeof(handle_map_node));
	if (new_node == NULL) {
		return NULL;
	}
	USER *new_user = user_create(handle);
	if (new_user == NULL) {
		return NULL;
	}
	new_node->user = new_user;
	new_node->handle = user_get_handle(new_user);
	new_node->next = NULL;
	return new_node;
}



void ureg_unregister(USER_REGISTRY *ureg, char *handle) {
	P(&ureg->registry_mutex);
	handle_map_node *node = ureg->head;
	handle_map_node *prev = NULL;
	while (node != NULL) {
		if (strcmp(handle, node->handle) == 0) {
			user_unref(node->user, "for removal from registry");
			if (prev != NULL) {
				prev->next = node->next;
			}
			free(node);
			break;
		}
		prev = node;
		node = node->next;
	}
	V(&ureg->registry_mutex);
}