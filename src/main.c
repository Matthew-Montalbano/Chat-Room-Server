#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "debug.h"
#include "server.h"
#include "globals.h"
#include "csapp.h"


static int should_terminate = 0;

static void terminate(int);
static void set_sighup_handler();
static void sighup_handler(int status);

/*
 * "Charla" chat server.
 *
 * Usage: charla <port>
 */
int main(int argc, char* argv[]){
    int listenfd;
    char *port;
    socklen_t clientlen;
    struct sockaddr_storage clientaddr;
    pthread_t tid;
    int *connfdp = NULL;
    if (argc != 3 || (strcmp(argv[1], "-p") != 0)) {
        fprintf(stderr, "Must use option '-p' to specify port number\n");
        exit(0);
    }
    port = argv[2];
    // Option processing should be performed here.
    // Option '-p <port>' is required in order to specify the port number
    // on which the server should listen.

    // Perform required initializations of the client_registry and
    // player_registry.
    user_registry = ureg_init();
    client_registry = creg_init();

    listenfd = open_listenfd(port);
    if (listenfd < 0) {
        fprintf(stderr, "Cannot open server on port %s\n", port);
        creg_fini(client_registry);
        ureg_fini(user_registry);
        exit(0);
    }
    debug("Process ID: %d", getpid());
    set_sighup_handler();
    while (!should_terminate) {
        clientlen = sizeof(struct sockaddr_storage);
        connfdp = Malloc(sizeof(int));
        *connfdp = accept(listenfd, (SA *) &clientaddr, &clientlen);
        if (*connfdp != -1) {
            Pthread_create(&tid, NULL, chla_client_service, connfdp);
            Pthread_detach(tid);
            connfdp = NULL;
        }
    }
    if (connfdp != NULL) {
        free(connfdp);
    }
    close(listenfd);
    terminate(0);
}

static void set_sighup_handler() {
    struct sigaction new_action;
    new_action.sa_handler = sighup_handler;
    sigemptyset(&new_action.sa_mask);
    new_action.sa_flags = 0;
    sigaction(SIGHUP, &new_action, NULL);
}

static void sighup_handler(int status) {
    should_terminate = 1;
}

/*
 * Function called to cleanly shut down the server.
 */
static void terminate(int status) {
    // Shut down all existing client connections.
    // This will trigger the eventual termination of service threads.
    creg_shutdown_all(client_registry);

    // Finalize modules.
    creg_fini(client_registry);
    ureg_fini(user_registry);

    debug("%ld: Server terminating", pthread_self());
    exit(status);
}
