#include <stdlib.h>

#include "mailbox.h"
#include "debug.h"
#include "csapp.h"

typedef struct queue_node {
	MAILBOX_ENTRY *entry;
	struct queue_node *next;
} QUEUE_NODE;

typedef struct queue {
	QUEUE_NODE *head;
	QUEUE_NODE *tail;
} QUEUE;

struct mailbox {
	QUEUE *queue;
	char *handle;
	int ref_count;
	int defunct;
	sem_t queue_mutex;
	sem_t ref_mutex;
	sem_t defunct_mutex;
	sem_t messages;
	MAILBOX_DISCARD_HOOK *discard_hook;
};

QUEUE *init_queue();
MAILBOX_ENTRY *init_message_entry(int msgid, MAILBOX *from, void *body, int length);
MESSAGE *init_message(int msgid, MAILBOX *from, void *body, int length);
QUEUE_NODE *init_queue_node(MAILBOX_ENTRY *entry);
MAILBOX_ENTRY *init_notice_entry(NOTICE_TYPE ntype, int msgid);
NOTICE *init_notice(NOTICE_TYPE ntype, int msgid);
MAILBOX_ENTRY *dequeue_entry(MAILBOX *mb);
void mb_fini(MAILBOX *mb);


MAILBOX *mb_init(char *handle) {
	char *private_handle = malloc(strlen(handle) + 1);
	if (private_handle == NULL) {
		return NULL;
	}
	strcpy(private_handle, handle);
	MAILBOX *mailbox = malloc(sizeof(MAILBOX));
	if (mailbox == NULL) {
		free(private_handle);
		return NULL;
	}

	mailbox->queue = init_queue();
	if (mailbox->queue == NULL) {
		free(private_handle);
		free(mailbox);
		return NULL;
	}
	mailbox->handle = private_handle;
	mailbox->ref_count = 1;
	mailbox->defunct = 0;
	Sem_init(&mailbox->queue_mutex, 0, 1);
	Sem_init(&mailbox->ref_mutex, 0, 1);
	Sem_init(&mailbox->defunct_mutex, 0, 1);
	Sem_init(&mailbox->messages, 0, 0);
	mailbox->discard_hook = NULL;
	return mailbox;
}

QUEUE *init_queue() {
	QUEUE *queue = malloc(sizeof(QUEUE));
	if (queue == NULL) {
		return NULL;
	}
	queue->head = NULL;
	queue->tail = NULL;
	return queue;
}


void mb_set_discard_hook(MAILBOX *mb, MAILBOX_DISCARD_HOOK *hook) {
	mb->discard_hook = hook;
}


void mb_ref(MAILBOX *mb, char *why) {
	P(&mb->ref_mutex);
	mb->ref_count++;
	debug("Increasing mailbox %p reference count (%d -> %d) %s", mb, mb->ref_count - 1, mb->ref_count, why);
	V(&mb->ref_mutex);
}


void mb_unref(MAILBOX *mb, char *why) {
	P(&mb->ref_mutex);
	mb->ref_count--;
	debug("Decreasing mailbox %p reference count (%d -> %d) %s", mb, mb->ref_count + 1, mb->ref_count, why);
	if (mb->ref_count == 0) {
		mb_fini(mb);
		debug("Freeing mailbox %p in finalization", mb);
		free(mb);
		return;
	}
	V(&mb->ref_mutex);
}

void mb_fini(MAILBOX *mb) {
	MAILBOX_ENTRY *entry;
	while ((entry = dequeue_entry(mb)) != NULL) {
		if (mb->discard_hook != NULL) {
			mb->discard_hook(entry);
		}
		if (entry->type == MESSAGE_ENTRY_TYPE) {
			if (entry->content.message.from != NULL) {
				mb_unref(entry->content.message.from, "for message from mailbox being removed in finalization");
			}
			free(entry->content.message.body);
		}
		free(entry);
	}
	free(mb->queue);
	free(mb->handle);
}


void mb_shutdown(MAILBOX *mb) {
	P(&mb->defunct_mutex);
	mb->defunct = 1;
	V(&mb->defunct_mutex);
	V(&mb->messages);
}


char *mb_get_handle(MAILBOX *mb) {
	return mb->handle;
}


void mb_add_message(MAILBOX *mb, int msgid, MAILBOX *from, void *body, int length) {
	MAILBOX_ENTRY *entry = init_message_entry(msgid, from, body, length);
	if (entry == NULL) {
		return;
	}
	P(&mb->queue_mutex);
	QUEUE *queue = mb->queue;
	QUEUE_NODE *node = init_queue_node(entry);
	if (node == NULL) {
		free(&entry->content.message);
		free(entry);
		V(&mb->queue_mutex);
		return;
	}
	if (from != NULL) {
		mb_ref(entry->content.message.from, "for mailbox being used in a message");
	}
	if (queue->tail == NULL) {
		queue->head = node;
		queue->tail = node;
	} else {
		queue->tail->next = node;
		queue->tail = node;
	}
	V(&mb->queue_mutex);
	V(&mb->messages);
}

MAILBOX_ENTRY *init_message_entry(int msgid, MAILBOX *from, void *body, int length) {
	MAILBOX_ENTRY *entry = malloc(sizeof(MAILBOX_ENTRY));
	if (entry == NULL) {
		return NULL;
	}
	entry->type = MESSAGE_ENTRY_TYPE;
	MESSAGE *message = &entry->content.message;
	message->msgid = msgid;
	message->from = from;
	message->body = body;
	message->length = length;
	return entry;
}

QUEUE_NODE *init_queue_node(MAILBOX_ENTRY *entry) {
	QUEUE_NODE *qn = malloc(sizeof(QUEUE_NODE));
	if (qn == NULL) {
		return NULL;
	}
	qn->entry = entry;
	qn->next = NULL;
	return qn;
}


void mb_add_notice(MAILBOX *mb, NOTICE_TYPE ntype, int msgid) {
	MAILBOX_ENTRY *entry = init_notice_entry(ntype, msgid);
	if (entry == NULL) {
		return;
	}
	P(&mb->queue_mutex);
	QUEUE *queue = mb->queue;
	QUEUE_NODE *node = init_queue_node(entry);
	if (node == NULL) {
		free(entry);
		V(&mb->queue_mutex);
		return;
	}
	if (queue->tail == NULL) {
		queue->head = node;
		queue->tail = node;
	} else {
		queue->tail->next = node;
		queue->tail = node;
	}
	V(&mb->queue_mutex);
	V(&mb->messages);
}


MAILBOX_ENTRY *init_notice_entry(NOTICE_TYPE ntype, int msgid) {
	MAILBOX_ENTRY *entry = malloc(sizeof(MAILBOX_ENTRY));
	if (entry == NULL) {
		return NULL;
	}
	entry->type = NOTICE_ENTRY_TYPE;
	NOTICE *notice = &entry->content.notice;
	notice->msgid = msgid;
	notice->type = ntype;
	return entry;
}


MAILBOX_ENTRY *mb_next_entry(MAILBOX *mb) {
	P(&mb->messages);
	P(&mb->defunct_mutex);
	MAILBOX_ENTRY *next_entry = NULL;
	if (!mb->defunct) {
		next_entry = dequeue_entry(mb);
	}
	V(&mb->defunct_mutex);
	return next_entry;
}

MAILBOX_ENTRY *dequeue_entry(MAILBOX *mb) {
	P(&mb->queue_mutex);
	QUEUE *queue = mb->queue;
	QUEUE_NODE *head = queue->head;
	MAILBOX_ENTRY *entry = NULL;
	if (head != NULL) {
		entry = queue->head->entry;
		if (queue->head == queue->tail) {
			queue->head = queue->tail = NULL;
		} else {
			queue->head = queue->head->next;
		}
		free(head);
	}
	V(&mb->queue_mutex);
	return entry;
}
