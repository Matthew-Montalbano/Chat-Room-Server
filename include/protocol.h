/**
 * === DO NOT MODIFY THIS FILE ===
 * If you need some other prototypes or constants in a header, please put them
 * in another header file.
 *
 * When we grade, we will be replacing this file with our own copy.
 * You have been warned.
 * === DO NOT MODIFY THIS FILE ===
 */
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * The "Charla" chat server protocol.
 *
 * This header file specifies the format of communication between the
 * Charla server and its clients.  To avoid confusion, we will use
 * the term "message" to refer to a message sent from one client to
 * another, and "packet" to refer to a single message sent at the
 * protocol level.  A full-duplex, stream-based (i.e. TCP) connection
 * is used between a client and the server.  Communication is effected
 * by the client and server sending packets to each other over this
 * connection.  Each packet consists of a fixed-length header, with
 * fields in network byte order, followed by a payload whose length is
 * specified in the header.  Each packet sent from a client to a
 * server engenders either a positive acknowledgement (ACK) or a
 * negative acknowledgement (NACK) notice from the server to the client.
 * In addition, the server may send other packets asynchronously to the
 * client.  These packets may be sent at any time and are not acknowledged
 * by the client.
 *
 * The following are the packet types in the protocol:
 *
 * Client-to-server requests, acknowledged by server:
 *   LOGIN:  Log client into the system
 *   LOGOUT: Log client out of the system
 *   UNAME: Get the user name associated with an integer user ID
 *   USERS: Get list of all users currently logged in to the system
 *   SEND: Send a message to a user
 *
 * Server-to-client notices, not acknowledged by client:
 *   ACK: Positive acknowledgement of previous server-to-client packet
 *   NACK: Negative acknowledgement of previous server-to_client packet
 *   MESG: Delivery of a message previously sent by SEND
 *   RCVD: Notice of successful delivery of a previously sent message
 *   BOUNCE: Notice of unsuccessful delivery of a previously sent message
 */

typedef enum {
    CHLA_NO_PKT,  // Unused
    CHLA_LOGIN_PKT, CHLA_LOGOUT_PKT, CHLA_USERS_PKT, CHLA_SEND_PKT,
    CHLA_ACK_PKT, CHLA_NACK_PKT, CHLA_MESG_PKT, CHLA_RCVD_PKT, CHLA_BOUNCE_PKT
} CHLA_PACKET_TYPE;

/*
 * Each message consists of a fixed size header, followed by a
 * variable-size payload.  Multi-byte fields in the header are in
 * network byte order.
 *
 * The following structure defines the header format:
 */
typedef struct {
    uint8_t type;		   // Type of the packet
    uint32_t payload_length;       // Length of payload
    uint32_t msgid;                // Message ID to which packet pertains
    uint32_t timestamp_sec;        // Seconds field of time packet was sent
    uint32_t timestamp_nsec;       // Nanoseconds field of time packet was sent
} CHLA_PACKET_HEADER;

/*
 * The msgid field in the packet header should contain a non-zero
 * client-generated value that uniquely identifies a particular
 * message.  The client may use any convenient technique to produce
 * the value stored in this field.  Possibilities are: message
 * sequence numbers, timestamps, and hashes of message content.  These
 * unique identifiers are not used by the Charla server; they are
 * simply passed through in order to permit a client to associate
 * notifications from the server (such as delivery and nondelivery
 * notifications) with the messages to which they pertain.
 *
 * The actual body of a message is sent in the variable-length payload
 * part of a packet, which immediately follows the fixed-length header
 * and which consists of exactly payload_length bytes of data.  The
 * first line of a message contains either the username of the intended
 * receiver (in case of a message being sent), or the username of the
 * sender (in case of a message being delivered).  This line is
 * terminated by the \r\n line termination sequence.  Following the
 * line termination sequence is the body of the message, which may be
 * in an arbitrary format (even binary).  The total number of bytes
 * contained in the first line of the message, plus the line
 * termination sequence, plus the message body must be exactly equal
 * to the payload_length specified in the packet header.
 *
 * Format of message sent by client:
 *   (username of receiver)\r\n(message body)
 *
 * Format of message delivered to client:
 *   (username of sender)\r\n(message body)
 *
 * In the case of a login request, the payload part of the packet
 * contains just the requested username and the message body is omitted.
 */

/*
 * Send a packet with a specified header and payload.
 *   fd - file descriptor on which packet is to be sent
 *   hdr - the packet header, with multi-byte fields in network byte order
 *   payload - pointer to packet payload, or NULL, if none.
 *
 * Multi-byte fields in the header are assumed to be in network byte order.
 *
 * On success, 0 is returned.
 * On error, -1 is returned and errno is set.
 */
int proto_send_packet(int fd, CHLA_PACKET_HEADER *hdr, void *payload);

/*
 * Receive a packet, blocking until one is available.
 *  fd - file descriptor from which packet is to be received
 *  hdr - pointer to caller-supplied storage for packet header
 *  payload - variable into which to store payload pointer
 *
 * The returned header has its multi-byte fields in network byte order.
 *
 * If the returned payload pointer is non-NULL, then the caller
 * is responsible for freeing the storage.
 *
 * On success, 0 is returned.
 * On error, -1 is returned, payload and length are left unchanged,
 * and errno is set.
 */
int proto_recv_packet(int fd, CHLA_PACKET_HEADER *hdr, void **payload);

#endif
