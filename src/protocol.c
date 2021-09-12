#include <stdlib.h>


#include "protocol.h"
#include "unistd.h"
#include "debug.h"


int write_all(int fd, void *buffer, int size);
int read_all(int fd, void *buffer, int size);

int proto_send_packet(int fd, CHLA_PACKET_HEADER *hdr, void *payload) {
	if (write_all(fd, hdr, sizeof(CHLA_PACKET_HEADER)) == -1) return -1;
	int payload_len = ntohl(hdr->payload_length);
	if (payload != NULL || payload_len > 0) {
		if (write_all(fd, payload, payload_len) == -1) return -1;
	}
	return 0;
}

int write_all(int fd, void *buffer, int size) {
	int total_bytes_written, bytes_written;
	total_bytes_written = bytes_written = 0;
		while (total_bytes_written != size) {
		bytes_written = write(fd, buffer, size - total_bytes_written);
		if (bytes_written == -1) {
			return -1;
		}
		total_bytes_written += bytes_written;
		buffer += bytes_written;
	}
	return 0;
}

int proto_recv_packet(int fd, CHLA_PACKET_HEADER *hdr, void **payload) {
	if (read_all(fd, hdr, sizeof(CHLA_PACKET_HEADER)) == -1) return -1;
	int payload_len = ntohl(hdr->payload_length);
	if (payload_len > 0) {
		void *buffer = malloc(payload_len);
		if (read_all(fd, buffer, payload_len) == -1) {
			free(buffer);
			return -1;
		}
		*payload = buffer;
	}
	return 0;
}

int read_all(int fd, void *buffer, int size) {
	int total_bytes_read, bytes_read;
	total_bytes_read = bytes_read = 0;
	while (total_bytes_read != size) {
		bytes_read = read(fd, buffer, size - total_bytes_read);
		if (bytes_read == -1 || bytes_read == 0) {
			return -1;
		}
		total_bytes_read += bytes_read;
		buffer += bytes_read;
	}
	return 0;
}