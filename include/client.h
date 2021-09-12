/**
 * === DO NOT MODIFY THIS FILE ===
 * If you need some other prototypes or constants in a header, please put them
 * in another header file.
 *
 * When we grade, we will be replacing this file with our own copy.
 * You have been warned.
 * === DO NOT MODIFY THIS FILE ===
 */
#ifndef CLIENT_H
#define CLIENT_H

#include "protocol.h"
#include "user.h"
#include "mailbox.h"
#include "client_registry.h"

// This declaration avoids some constraints on the order of includes.
typedef struct client_registry CLIENT_REGISTRY;

/*
 * A CLIENT represents the state of a network client connected to the
 * system.  It contains the file descriptor of the connection to the
 * client and it provides functions for sending packets to the client.
 * If the client is logged in as a particular user, it contains a
 * reference to a USER object and to a MAILBOX object.  CLIENT objects
 * are managed by the client registry.  So that a CLIENT object can be
 * passed around externally to the client registry without fear of dangling
 * references, it has a reference count that corresponds to the number of
 * references that exist to the object.  A CLIENT object will not be freed
 * until its reference count reaches zero.
 *
 * All messages for a client should be sent through the CLIENT object,
 * which serializes concurrent calls so that they don't interfere with
 * each other.
 */

/*
 * The CLIENT type is a structure type that defines the state of a client.
 * You will have to give a complete structure definition in client.c.
 * The precise contents are up to you.  Be sure that all the operations
 * that might be called concurrently are thread-safe.
 */
typedef struct client CLIENT;

/*
 * Create a new CLIENT object with a specified file descriptor with which
 * to communicate with the client.  The returned CLIENT has a reference
 * count of one and is in the logged-out state.
 *
 * @param creg  The client registry in which to create the client.
 * @param fd  File descriptor of a socket to be used for communicating
 * with the client.
 * @return  The newly created CLIENT object, if creation is successful,
 * otherwise NULL.
 */
CLIENT *client_create(CLIENT_REGISTRY *creg, int fd);

/*
 * Increase the reference count on a CLIENT by one.
 *
 * @param client  The CLIENT whose reference count is to be increased.
 * @param why  A string describing the reason why the reference count is
 * being increased.  This is used for debugging printout, to help trace
 * the reference counting.
 * @return  The same CLIENT that was passed as a parameter.
 */
CLIENT *client_ref(CLIENT *client, char *why);

/*
 * Decrease the reference count on a CLIENT by one.  If after
 * decrementing, the reference count has reached zero, then the CLIENT
 * and its contents are freed.
 *
 * @param client  The CLIENT whose reference count is to be decreased.
 * @param why  A string describing the reason why the reference count is
 * being decreased.  This is used for debugging printout, to help trace
 * the reference counting.
 */
void client_unref(CLIENT *client, char *why);

/*
 * Log this CLIENT in under a specified handle.
 * The handle is registered with the user registry, creating a new
 * USER object corresponding to the handle if one did not already
 * exist.  A MAILBOX is also created and retained by the CLIENT.
 * The login fails if the CLIENT is already logged in or there is already
 * some other CLIENT that is logged under the specified handle.
 * Otherwise, the login is successful and the CLIENT is marked as "logged in".
 *
 * @param CLIENT  The CLIENT that is to be logged in.
 * @param handle  The handle under which the CLIENT is to be logged in.
 * @return 0 if the login operation is successful, otherwise -1.
 */
int client_login(CLIENT *client, char *handle);

/*
 * Log out this CLIENT.  If the client was not logged in, then it is
 * an error.  The references to the USER and MAILBOX that were saved
 * when the CLIENT was logged in are discarded.
 *
 * @param client  The CLIENT that is to be logged out.
 * @return 0 if the client was logged in and has been successfully
 * logged out, otherwise -1.
 */
int client_logout(CLIENT *client);

/*
 * Get the USER object for the specified logged-in CLIENT.
 *
 * @param client  The CLIENT from which to get the USER.
 * @param no_ref  If nonzero, then the reference count on the returned
 * USER is *not* incremented.  This is a convenience feature that
 * should only be used if the caller knows that the CLIENT cannot
 * be logged out until the USER object is no longer needed.
 * Otherwise, the caller should pass a zero value for no_ref and
 * accept the responsibility for decrementing the reference count
 * when finished with the USER object.
 */
USER *client_get_user(CLIENT *client, int no_ref);

/*
 * Get the MAILBOX for the specified logged-in CLIENT.
 *
 * @param client  The CLIENT from which to get the MAILBOX.
 * @param no_ref  If nonzero, then the reference count on the returned
 * MAILBOX is *not* incremented.  This is a convenience feature that
 * should only be used if the caller knows that the CLIENT cannot
 * be logged out until the MAILBOX object is no longer needed.
 * Otherwise, the caller should pass a zero value for no_ref and
 * accept the responsibility for decrementing the reference count
 * when finished with the MAILBOX object.
 * @return  The MAILBOX that the CLIENT is currently using,
 * otherwise NULL if the client is not currently logged in.
 */
MAILBOX *client_get_mailbox(CLIENT *client, int no_ref);

/*
 * Get the file descriptor for the network connection associated with
 * this CLIENT.  The file descriptor is set at the time the CLIENT
 * is created and does not change.
 *
 * @param client  The CLIENT for which the file descriptor is to be
 * obtained.
 * @return the file descriptor.
 */
int client_get_fd(CLIENT *client);

/*
 * Send a packet to a client.  Exclusive access to the network connection
 * is obtained for the duration of this operation, to prevent concurrent
 * invocations from corrupting each other's transmissions.  To prevent
 * such interference, only this function should be used to send packets to
 * the client, rather than the lower-level proto_send_packet() function.
 *
 * @param client  The CLIENT who should be sent the packet.
 * @param pkt  The header of the packet to be sent.
 * @param data  Data payload to be sent, or NULL if none.
 * @return 0 if transmission succeeds, -1 otherwise.
 */
int client_send_packet(CLIENT *user, CHLA_PACKET_HEADER *pkt, void *data);

/*
 * Send an ACK packet to a client.  This is a convenience function that
 * streamlines a common case.
 *
 * @param client  The CLIENT who should be sent the packet.
 * @param msgid  Message ID (in host byte order) to which the ACK pertains.
 * @param data  Pointer to the optional data payload for this packet,
 * or NULL if there is to be no payload.
 * @param datalen  Length of the data payload, or 0 if there is none.
 * @return 0 if transmission succeeds, -1 otherwise.
 */
int client_send_ack(CLIENT *client, uint32_t msgid, void *data, size_t datalen);

/*
 * Send an NACK packet to a client.  This is a convenience function that
 * streamlines a common case.
 *
 * @param client  The CLIENT to be sent the packet.
 * @param msgid  Message ID to which the ACK pertains.
 * @return 0 if transmission succeeds, -1 otherwise.
 */
int client_send_nack(CLIENT *client, uint32_t msgid);

#endif
