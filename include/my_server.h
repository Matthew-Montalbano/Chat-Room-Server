#ifndef MY_SERVER_H
#define MY_SERVER_H

void *chla_mailbox_service(void *arg);
void ignore_sigpipe();
void send_bounce(MAILBOX_ENTRY *entry);

int process_login(CLIENT *client, void *payload, pthread_t *tid);
char *get_username(void *payload);
void *get_message(void *payload, int payload_len, int *message_length);
void send_server_response(int status, CLIENT *client, uint32_t msgid);

void process_users(CLIENT *client, uint32_t msgid);
char *get_list_of_handles(int *payload_length);
int get_num_clients(CLIENT **clients);
char **get_handles(CLIENT **clients, int num_clients, int *num_users, int *payload_len);
char *handles_list_to_str(char **handles, int num_users, int handles_str_len);

int process_send(CLIENT *client, void *payload, int payload_len, uint32_t msgid);
CLIENT *receiver_logged_in(char *receiver_handle);
char *create_message(MAILBOX *receiver_mb, char *message, int message_len, int *payload_len);

void send_message(MESSAGE *message, CLIENT *client, MAILBOX *client_mb);
CHLA_PACKET_HEADER *create_header(uint8_t type, uint32_t payload_len, uint32_t msgid);
void send_notice(NOTICE *notice, CLIENT *client);

#endif