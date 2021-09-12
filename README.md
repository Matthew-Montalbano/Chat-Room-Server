# Chat-Room-Server
A backend chat room server written in C, allowing provided client application instances to communicate with each other.

## Features
- Server maintains a separate thread for each connected client application, handling the concurrent requests of up to 64 clients
- Unique mailbox service threads handle the queue of incoming messages for each client from other users
- Clients notified when message has been delivered or if delivery fails
- Client and user registries keep track of all connected clients and logged-in users
