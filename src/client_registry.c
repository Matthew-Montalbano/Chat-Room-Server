#include <string.h>

#include "client_registry.h"
#include "csapp.h"
#include "debug.h"

struct client_registry {
	CLIENT *clients[MAX_CLIENTS];
	int num_clients;
	sem_t registry_mutex, count_sem;
};

void init_registry_array(CLIENT_REGISTRY *registry);

CLIENT_REGISTRY *creg_init() {
	CLIENT_REGISTRY *registry = malloc(sizeof(CLIENT_REGISTRY));
	if (registry == NULL) {
		return NULL;
	}
	init_registry_array(registry);
	registry->num_clients = 0;
	Sem_init(&registry->count_sem, 0, 1);
	Sem_init(&registry->registry_mutex, 0, 1);
	debug("Initialize client registry");
	return registry;
}

void init_registry_array(CLIENT_REGISTRY *registry) {
	for (int i = 0; i < MAX_CLIENTS; i++) {
		registry->clients[i] = NULL;
	}
}

void creg_fini(CLIENT_REGISTRY *cr) {
	P(&cr->registry_mutex);
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (cr->clients[i] != NULL) {
			client_unref(cr->clients[i], "for removal from registry in cleanup");
			cr->clients[i] = NULL;
		}
	}
	V(&cr->registry_mutex);
	free(cr);
	debug("Finalize client registry");
}

CLIENT *creg_register(CLIENT_REGISTRY *cr, int fd) {
	CLIENT *client = NULL;
	P(&cr->registry_mutex);
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (cr->clients[i] == NULL) {
			cr->num_clients++;
			if (cr->num_clients == 1) {
				P(&cr->count_sem);
			}
			client = client_create(cr, fd);
			cr->clients[i] = client;
			client_ref(client, "for returning pointer from registry");
			break;
		}
	}
	V(&cr->registry_mutex);
	return client;
}

int creg_unregister(CLIENT_REGISTRY *cr, CLIENT *client) {
	int success = -1;
	int client_fd = client_get_fd(client);
	P(&cr->registry_mutex);
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (cr->clients[i] != NULL && client_get_fd(cr->clients[i]) == client_fd) {
			client_unref(client, "for removal from registry");
			cr->clients[i] = NULL;
			cr->num_clients--;
			success = 0;
			break;
		}
	}
	if (success == 0 && cr->num_clients == 0) {
		V(&cr->count_sem);
	}
	V(&cr->registry_mutex);
	return success;
}

CLIENT **creg_all_clients(CLIENT_REGISTRY *cr) {
	int arr_index = 0;
	P(&cr->registry_mutex);
	CLIENT **client_arr = malloc(sizeof(CLIENT *) * (cr->num_clients + 1));
	if (client_arr != NULL) {
		for (int i = 0; i < MAX_CLIENTS; i++) {
			if (cr->clients[i] != NULL) {
				client_arr[arr_index] = cr->clients[i];
				client_ref(cr->clients[i], "for all clients being retrieved");
				arr_index++;
			}
		}
		client_arr[cr->num_clients] = NULL;
	}
	V(&cr->registry_mutex);
	return client_arr;
}

void creg_shutdown_all(CLIENT_REGISTRY *cr) {
	P(&cr->registry_mutex);
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (cr->clients[i] != NULL) {
			debug("Shutting down client %d", client_get_fd(cr->clients[i]));
			shutdown(client_get_fd(cr->clients[i]), SHUT_RDWR);
		}
	}
	V(&cr->registry_mutex);
	P(&cr->count_sem);
	V(&cr->count_sem);
}