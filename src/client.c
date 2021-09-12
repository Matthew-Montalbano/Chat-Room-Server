#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "client_registry.h"
#include "debug.h"
#include "csapp.h"
#include "globals.h"

struct client {
	int fd;
	int ref_count;
	USER *user;
	MAILBOX *mailbox;
	sem_t fd_mutex;
	sem_t ref_mutex;
	sem_t user_mutex;
	sem_t mailbox_mutex;
};

static sem_t login_mutex;
static void init_login_mutex(void);
int check_logged_in(char *handle);

CHLA_PACKET_HEADER *create_header(uint8_t type, uint32_t payload_len, uint32_t msgid);

CLIENT *client_create(CLIENT_REGISTRY *creg, int fd) {
	CLIENT *client = malloc(sizeof(CLIENT));
	if (client == NULL) return NULL;
	client->fd = fd;
	client->ref_count = 1;
	client->user = NULL;
	client->mailbox = NULL;
	Sem_init(&client->fd_mutex, 0, 1);
	Sem_init(&client->ref_mutex, 0, 1);
	Sem_init(&client->user_mutex, 0, 1);
	Sem_init(&client->mailbox_mutex, 0, 1);
	return client;
}

CLIENT *client_ref(CLIENT *client, char *why) {
	P(&client->ref_mutex);
	client->ref_count += 1;
	debug("Increasing client %p reference count (%d -> %d) %s", client, client->ref_count - 1, client->ref_count, why);
	V(&client->ref_mutex);
	return client;
}

void client_unref(CLIENT *client, char *why) {
	P(&client->ref_mutex);
	client->ref_count -= 1;
	debug("Decreasing client %p reference count (%d -> %d) %s", client, client->ref_count + 1, client->ref_count, why);
	if (client->ref_count == 0) {
		debug("Freeing client %p", client);
		free(client);
		return;
	}
	V(&client->ref_mutex);
}

int client_login(CLIENT *client, char *handle) {
	static pthread_once_t once = PTHREAD_ONCE_INIT;
	Pthread_once(&once, init_login_mutex);
	debug("Client %p attempting login to handle %s", client, handle);
	P(&login_mutex);
	P(&client->user_mutex);
	P(&client->mailbox_mutex);
	int login_status = -1;
	if (client->user == NULL && client->mailbox == NULL) {
		V(&client->mailbox_mutex);
		V(&client->user_mutex);
		int logged_in = check_logged_in(handle);
		P(&client->user_mutex);
		P(&client->mailbox_mutex);
		if (logged_in == 0) {
			USER *user = ureg_register(user_registry, handle);
			if (user != NULL) {
				client->user = user;
				client->mailbox = mb_init(handle);
				login_status = 0;
			}
		}
	}
	V(&client->mailbox_mutex);
	V(&client->user_mutex);
	V(&login_mutex);
	return login_status;
}

int check_logged_in(char *handle) {
	CLIENT **original_clients = creg_all_clients(client_registry);
	if (original_clients == NULL) {
		return -1;
	}
	char *curr_handle;
	USER *user;
	CLIENT **clients = original_clients;
	int logged_in = 0;
	while (*clients != NULL) {
		P(&(*clients)->user_mutex);
		user = (*clients)->user;
		if (user != NULL) {
			curr_handle = user_get_handle(user);
			if (strcmp(curr_handle, handle) == 0) {
				logged_in = 1;
			}
		}
		client_unref(*clients, "for creg_all_clients ref no longer needed");
		V(&(*clients)->user_mutex);
		clients++;
	}
	free(original_clients);
	return logged_in;
}

static void init_login_mutex(void) {
	Sem_init(&login_mutex, 0, 1);
}

int client_logout(CLIENT *client) {
	int return_code = -1;
	P(&client->user_mutex);
	P(&client->mailbox_mutex);
	if (client->user != NULL && client->mailbox != NULL) {
		user_unref(client->user, "for client logging out");
		mb_shutdown(client->mailbox);
		mb_unref(client->mailbox, "for client logging out");
		client->user = NULL;
		client->mailbox = NULL;
		return_code = 0;
	}
	V(&client->mailbox_mutex);
	V(&client->user_mutex);
	return return_code;
}

USER *client_get_user(CLIENT *client, int no_ref) {
	USER *user = NULL;
	P(&client->user_mutex);
	if (client->user != NULL) {
		if (no_ref == 0) {
			user_ref(client->user, "for client returning user");
		}
		user = client->user;
	}
	V(&client->user_mutex);
	return user;
}

MAILBOX *client_get_mailbox(CLIENT *client, int no_ref) {
	MAILBOX *mailbox = NULL;
	P(&client->mailbox_mutex);
	if (client->mailbox != NULL) {
		if (no_ref == 0) {
			mb_ref(client->mailbox, "for client returning mailbox");
		}
		mailbox = client->mailbox;
	}
	V(&client->mailbox_mutex);
	return mailbox;
}

int client_get_fd(CLIENT *client) {
	return client->fd;
}

int client_send_packet(CLIENT *user, CHLA_PACKET_HEADER *pkt, void *data) {
	int successful;
	P(&user->fd_mutex);
	successful = proto_send_packet(user->fd, pkt, data);
	V(&user->fd_mutex);
	debug("Sent packet (fd=%d, type=%d) for client %p", user->fd, pkt->type, user);
	return successful;
}

int client_send_ack(CLIENT *client, uint32_t msgid, void *data, size_t datalen) {
	CHLA_PACKET_HEADER *header = create_header(CHLA_ACK_PKT, htonl(datalen), htonl(msgid));
	if (header == NULL) {
		return -1;
	}
	int success = client_send_packet(client, header, data);
	free(header);
	return success;
}

CHLA_PACKET_HEADER *create_header(uint8_t type, uint32_t payload_len, uint32_t msgid) {
	CHLA_PACKET_HEADER *header = malloc(sizeof(CHLA_PACKET_HEADER));
	if (header == NULL) {
		return NULL;
	}
	memset(header, 0, sizeof(CHLA_PACKET_HEADER));
	header->type = type;
	header->payload_length = payload_len;
	header->msgid = msgid;
	struct timespec spec;
	clock_gettime(CLOCK_REALTIME, &spec);
	header->timestamp_sec = htonl(spec.tv_sec);
	header->timestamp_nsec = htonl(spec.tv_nsec);
	return header;
}

int client_send_nack(CLIENT *client, uint32_t msgid) {
	CHLA_PACKET_HEADER *header = create_header(CHLA_NACK_PKT, 0, htonl(msgid));
	if (header == NULL) {
		return -1;
	}
	int success = client_send_packet(client, header, NULL);
	free(header);
	return success;
}