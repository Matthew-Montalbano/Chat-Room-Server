#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#include "mailbox.h"
#include "client_registry.h"
#include "protocol.h"
#include "debug.h"
#include "csapp.h"
#include "globals.h"
#include "my_server.h"
#include "server.h"


void *chla_client_service(void *arg) {
	int fd = *((int *) arg);
	free(arg);
	CLIENT *client = creg_register(client_registry, fd);
	if (client == NULL) {
		debug("Max number of clients reached");
		return NULL;
	}
	CHLA_PACKET_HEADER *header = malloc(sizeof(CHLA_PACKET_HEADER));
	if (header == NULL) {
		return NULL;
	}
	ignore_sigpipe();
	void *payload = NULL;
	int status;
	pthread_t mb_service_thread_id = -1;
	while (proto_recv_packet(fd, header, &payload) != -1) {
		if (header->type == CHLA_LOGIN_PKT) {
			debug("Packet type: LOGIN");
			status = process_login(client, payload, &mb_service_thread_id);
			send_server_response(status, client, ntohl(header->msgid));
		} else if (header->type == CHLA_LOGOUT_PKT) {
			debug("Packet type: LOGOUT");
			status = client_logout(client);
			send_server_response(status, client, ntohl(header->msgid));
			if (status == 0) {
				pthread_join(mb_service_thread_id, NULL);
			}
		} else if (header->type == CHLA_USERS_PKT) {
			debug("Packet type: USERS");
			process_users(client, ntohl(header->msgid));
		} else if (header->type == CHLA_SEND_PKT) {
			debug("Packet type: SEND");
			status = process_send(client, payload, ntohl(header->payload_length), ntohl(header->msgid));
			send_server_response(status, client, ntohl(header->msgid));
		}
		if (payload != NULL) {
			free(payload);
			payload = NULL;
		}
	}
	if (client_logout(client) == 0) {
		pthread_join(mb_service_thread_id, NULL);
	}
	free(header);
	client_unref(client, "for client reference being discarded in client service shutdown");
	creg_unregister(client_registry, client);
	close(fd);
	return NULL;
}

void ignore_sigpipe() {
	struct sigaction action;
	action.sa_handler = SIG_IGN;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	sigaction(SIGPIPE, &action, NULL);
}

char *get_username(void *payload) {
	char *char_payload = (char *) payload;
	int user_length = 0;
	while (*char_payload != '\r') {
		debug("%c", *char_payload);
		user_length++;
		char_payload++;
	}
	char *username = malloc(user_length + 1);
	if (username == NULL) {
		return NULL;
	}
	strncpy(username, payload, user_length);
	username[user_length] = '\0';
	return username;
}

void *get_message(void *payload, int payload_len, int *message_length) {
	char *char_payload = (char *) payload;
	int non_message_length = 0;
	while (*char_payload != '\r') {
		non_message_length++;
		char_payload++;
	}
	non_message_length += 2;
	int message_len = payload_len - non_message_length;
	void *message = malloc(message_len);
	if (message == NULL) {
		return NULL;
	}
	memcpy(message, payload + non_message_length, message_len);
	*message_length = message_len;
	return message;
}

int process_login(CLIENT *client, void *payload, pthread_t *tid) {
	int login_status = -1;
	char *handle = get_username(payload);
	if (handle != NULL) {
		if (client_login(client, handle) == 0) {
			debug("Starting mailbox service for: %s (fd=%d)", handle, client_get_fd(client));
			Pthread_create(tid, NULL, chla_mailbox_service, client);

			login_status = 0;
		}
		free(handle);
	}
	return login_status;
}

void send_server_response(int status, CLIENT *client, uint32_t msgid) {
	if (status == -1) {
		client_send_nack(client, msgid);
	} else {
		client_send_ack(client, msgid, NULL, 0);
	}
}

void process_users(CLIENT *client, uint32_t msgid) {
	int payload_len;
	void *handles;
	if ((handles = get_list_of_handles(&payload_len)) == NULL) {
		client_send_nack(client, msgid);
	} else {
		client_send_ack(client, msgid, handles, payload_len);
		free(handles);
	}
}

char *get_list_of_handles(int *payload_length) {
	CLIENT **clients = creg_all_clients(client_registry);
	if (clients == NULL) {
		return NULL;
	}
	int num_clients = get_num_clients(clients);
	int all_handles_len, num_users;
	char **handles = get_handles(clients, num_clients, &num_users, &all_handles_len);
	char *handles_str = handles_list_to_str(handles, num_users, all_handles_len);
	free(handles);
	free(clients);
	if (handles_str == NULL) {
		return NULL;
	}
	*payload_length = all_handles_len + num_users; //for '\n' after each user
	return handles_str;
}

int get_num_clients(CLIENT **clients) {
	int num_clients = 0;
	while (*clients != NULL) {
		num_clients++;
		clients++;
	}
	return num_clients;
}

char **get_handles(CLIENT **clients, int num_clients, int *num_users, int *payload_len) {
	char **handles = malloc(sizeof(char *) * num_clients);
	if (handles == NULL) {
		return NULL;
	}
	USER *user;
	int users = 0;
	int payload_length = 0;
	while (*clients != NULL) {
		if ((user = client_get_user(*clients, 0)) != NULL) {
			handles[users] = user_get_handle(user);
			user_unref(user, "for user no longer needed");
			payload_length += strlen(handles[users]);
			users++;
		}
		client_unref(*clients, "for client from client list no longer needed");
		clients++;
	}
	*num_users = users;
	*payload_len = payload_length;
	return handles;
}

char *handles_list_to_str(char **handles, int num_users, int handles_str_len) {
	char *handles_str = malloc(handles_str_len + num_users); //for '\n' after each user
	if (handles_str == NULL) {
		return NULL;
	}
	char *handles_str_start = handles_str;
	int str_len;
	for (int i = 0; i < num_users; i++) {
		str_len = strlen(*handles);
		strncpy(handles_str, *handles, str_len);
		handles_str[str_len] = '\n';
		handles_str += str_len + 1;
		handles++;
	}
	return handles_str_start;
}

int process_send(CLIENT *client, void *payload, int payload_len, uint32_t msgid) {
	int send_status = -1;
	if (client_get_user(client, 1) != NULL) {
		char *receiver_handle = get_username(payload);
		CLIENT *receiver_client;
		if ((receiver_client = receiver_logged_in(receiver_handle)) != NULL) {
			MAILBOX *sender_mb = client_get_mailbox(client, 1);
			MAILBOX *receiver_mb = client_get_mailbox(receiver_client, 0);
			if (receiver_mb != NULL) {
				int message_len;
				void *message_body = get_message(payload, payload_len, &message_len);
				void *message = create_message(sender_mb, message_body, message_len, &message_len);
				if (receiver_mb != sender_mb) {
					mb_add_message(receiver_mb, msgid, sender_mb, message, message_len);
				} else {
					mb_add_message(receiver_mb, msgid, NULL, message, message_len);
				}
				mb_unref(receiver_mb, "now that message has been added to recipient's mailbox");
				free(message_body);
				send_status = 0;
			}
		}
		free(receiver_handle);
	}
	return send_status;
}


CLIENT *receiver_logged_in(char *receiver_handle) {
	CLIENT **clients = creg_all_clients(client_registry);
	if (clients == NULL) {
		return NULL;
	}
	USER *user;
	char *handle;
	CLIENT **clients_start = clients;
	CLIENT *receiver_client = NULL;
	while (*clients != NULL) {
		if (receiver_client == NULL && (user = client_get_user(*clients, 0)) != NULL) {
			handle = user_get_handle(user);
			user_unref(user, "for no longer needed");
			if (strcmp(handle, receiver_handle) == 0) {
				receiver_client = *clients;
			}
		}
		client_unref(*clients, "for client from client list no longer needed");
		clients++;
	}
	free(clients_start);
	return receiver_client;
}


char *create_message(MAILBOX *sender_mb, char *message, int message_len, int *payload_len) {
	char *sender_handle = mb_get_handle(sender_mb);
	int handle_len = strlen(sender_handle);
	int full_length = handle_len + 2 + message_len;
	void *full_message = malloc(full_length);
	if (full_message == NULL) {
		return NULL;
	}
	memcpy(full_message, sender_handle, handle_len);
	memcpy(full_message + handle_len, "\r\n", 2);
	memcpy(full_message + handle_len + 2, message, message_len);
	*payload_len = full_length;
	return full_message;
}


void *chla_mailbox_service(void *arg) {
	CLIENT *client = (CLIENT *) arg;
	client_ref(client, "for client being retained by mailbox service thread");
	MAILBOX *mb = client_get_mailbox(client, 0);
	if (mb == NULL) {
		client_unref(client, "for reference being discarded in mailbox service thread shutdown");
		return NULL;
	}
	mb_set_discard_hook(mb, send_bounce);
	MAILBOX_ENTRY *entry;
	while ((entry = mb_next_entry(mb)) != NULL) {
		if (entry->type == MESSAGE_ENTRY_TYPE) {
			send_message(&entry->content.message, client, mb);
			free(entry->content.message.body);
		} else {
			send_notice(&entry->content.notice, client);
		}
		//debug("Freeing entry content: entry->%p\tcontent->%p", entry, &entry->content.message);
		//free(&entry->content);;
		free(entry);
	}
	mb_unref(mb, "for reference being discared in mailbox service thread shutdown");
	client_unref(client, "for reference being discarded in mailbox service thread shutdown");
	return NULL;
}

void send_message(MESSAGE *message, CLIENT *client, MAILBOX *client_mb) {
	if (message->from == NULL) {
		debug("Process message (msgid=%d, from=%s)", message->msgid, mb_get_handle(client_mb));
	} else {
		debug("Process message (msgid=%d, from=%s)", message->msgid, mb_get_handle(message->from));
	}
	CHLA_PACKET_HEADER *header = create_header(CHLA_MESG_PKT, htonl(message->length), htonl(message->msgid));
	if (client_send_packet(client, header, message->body) == 0) {
		if (message->from != NULL) {
			mb_add_notice(message->from, RRCPT_NOTICE_TYPE, message->msgid);
		} else {
			mb_add_notice(client_mb, RRCPT_NOTICE_TYPE, message->msgid);
		}
	}
	if (message->from != NULL) {
		mb_unref(message->from, "for reference to sender's mailbox held by message being removed");
	}
	free(header);
}

void send_notice(NOTICE *notice, CLIENT *client) {
	debug("Process notice (type=%d)", notice->type);
	uint8_t header_type;
	if (notice->type == RRCPT_NOTICE_TYPE) {
		header_type = CHLA_RCVD_PKT;
	} else {
		header_type = CHLA_BOUNCE_PKT;
	}
	CHLA_PACKET_HEADER *header = create_header(header_type, 0, htonl(notice->msgid));
	client_send_packet(client, header, NULL);
	free(header);
}


void send_bounce(MAILBOX_ENTRY *entry) {
	if (entry == NULL || entry->type != MESSAGE_ENTRY_TYPE || entry->content.message.from == NULL) {
		return;
	}
	mb_add_notice(entry->content.message.from, BOUNCE_NOTICE_TYPE, entry->content.message.msgid);
	//mb_unref(entry->content.message.from, "for reference to sender's mailbox held by message being removed");
}