/**
 * === DO NOT MODIFY THIS FILE ===
 * If you need some other prototypes or constants in a header, please put them
 * in another header file.
 *
 * When we grade, we will be replacing this file with our own copy.
 * You have been warned.
 * === DO NOT MODIFY THIS FILE ===
 */
#ifndef CLIENT_REGISTRY_H
#define CLIENT_REGISTRY_H

#include "client.h"

/*
 * A client registry keeps track of the clients that are currently connected.
 * Each time a client connects, a new CLIENT object is created and added to
 * the registry.  When the thread servicing a client is about to terminate,
 * it removes the CLIENT object from the registry.  The client registry also
 * provides a function for shutting down all client connections and waiting
 * for all server threads to terminate.  Such a function is useful, for example,
 * in order to achieve clean server termination: when termination is desired,
 * the "main" thread will shut down all client connections and then wait for
 * all server threads to terminate before exiting the server process.
 */

/*
 * The maximum number of simultaneous clients supported by the registry.
 */
#define MAX_CLIENTS 64

/*
 * The CLIENT_REGISTRY type is a structure that defines the state of a
 * client registry.  You will have to give a complete structure
 * definition in client_registry.c.  The precise contents are up to
 * you.  Be sure that all the operations that might be called
 * concurrently are thread-safe.
 */
typedef struct client_registry CLIENT_REGISTRY;

/*
 * Initialize a new client registry.
 *
 * @return  the newly initialized client registry, or NULL if initialization
 * fails.
 */
CLIENT_REGISTRY *creg_init();

/*
 * Finalize a client registry, freeing all associated resources.
 *
 * @param cr  The client registry to be finalized, which must not
 * be referenced again.
 */
void creg_fini(CLIENT_REGISTRY *cr);

/*
 * Register a client connection.
 * If successful, returns a reference to the the newly registered CLIENT,
 * otherwise NULL.  The returned CLIENT has a reference count of two:
 * one for the pointer retained by the registry and one for the pointer
 * returned to the caller.
 *
 * @param cr  The client registry.
 * @param fd  The file descriptor of the connection to the client.
 * @return a reference to the newly registered CLIENT, if registration
 * is successful, otherwise NULL.
 */
CLIENT *creg_register(CLIENT_REGISTRY *cr, int fd);

/*
 * Unregister a CLIENT, removing it from the registry.
 * The file descriptor associated with the client connection is *not*
 * closed by this function; that remains the responsibility of whomever
 * originally obtained it.
 * It is an error if the CLIENT is not among the currently registered
 * clients at the time this function is called.
 * The reference count of the CLIENT is decreased by one to account
 * for the pointer being discarded.  If this results in the number of
 * connected clients reaching zero, then any threads waiting in
 * creg_shutdown_all() are allowed to proceed.
 *
 * @param cr  The client registry.
 * @param client  The CLIENT to be unregistered.
 * @return 0  if unregistration succeeds, otherwise -1.
 */
int creg_unregister(CLIENT_REGISTRY *cr, CLIENT *client);

/*
 * Return a list of all currently connected clients.  The result is
 * returned as a malloc'ed array of CLIENT pointers, with a NULL
 * pointer marking the end of the array.  Each CLIENT in the array
 * has had its reference count incremented by one, to account for
 * the pointer stored in the array.  It is the caller's responsibility
 * to decrement the reference count of each of the entries and to
 * free the array when it is no longer needed.
 *
 * @param cr  The registry from which the set of clients is to be
 * obtained.
 * @return the list of clients as a NULL-terminated array.
 */
CLIENT **creg_all_clients(CLIENT_REGISTRY *cr);

/*
 * Shut down (using shutdown(2)) all the sockets for connections
 * to currently registered clients.  The calling thread will block
 * in this function until all the server threads have recognized
 * the EOF on their connections caused by the socket shutdown and
 * have unregistered the corresponding clients.  This function
 * returns only when the number of registered clients has reached zero.
 * This function may be called more than once, but not concurrently.
 * Calling this function does not finalize the client registry.
 *
 * @param cr  The client registry.
 */
void creg_shutdown_all(CLIENT_REGISTRY *cr);

#endif
