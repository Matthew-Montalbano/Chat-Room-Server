/**
 * === DO NOT MODIFY THIS FILE ===
 * If you need some other prototypes or constants in a header, please put them
 * in another header file.
 *
 * When we grade, we will be replacing this file with our own copy.
 * You have been warned.
 * === DO NOT MODIFY THIS FILE ===
 */
#ifndef SERVER_H
#define SERVER_H

/*
 * Thread function for the thread that handles client requests.
 *
 * The arg pointer points to the file descriptor of client connection.
 * This pointer must be freed after the file descriptor has been retrieved.
 */
void *chla_client_service(void *arg);

#endif
