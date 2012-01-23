/*
 * msg_queue.h: a generic process messaging queue implementation
 * Copyright (c) 2012 Rong Shen <rong1129@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#ifndef _MSG_QUEUE_H
#define _MSG_QUEUE_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <linux/poll.h>


#define DEFAULT_MAX_QUEUE_LENGTH		100


typedef void (*msg_release_handler)(struct list_head *);


struct msg_queue {
	spinlock_t lock;
	int active;
	
	size_t num_msgs, max_msgs;
	struct list_head msgs;

	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;

	struct rb_node rb_node;
	int usage; 

	msg_release_handler release;
};


extern struct msg_queue *create_msg_queue(size_t max_msgs, msg_release_handler handler);
extern int free_msg_queue(struct msg_queue *q);

extern int get_msg_queue(struct msg_queue *q);
extern int put_msg_queue(struct msg_queue *q);

extern int write_msg_queue(struct msg_queue *q, struct list_head *msg);
extern int write_msg_queue_head(struct msg_queue *q, struct list_head *msg);

extern int read_msg_queue(struct msg_queue *q, struct list_head **pmsg);
extern int read_msg_queue_tail(struct msg_queue *q, struct list_head **pmsg);

static inline int msg_queue_empty(struct msg_queue *q)
{
	return (q->num_msgs < 1);
}

static inline int msg_queue_full(struct msg_queue *q)
{
	return (q->num_msgs >= q->max_msgs);
}

static inline size_t msg_queue_size(struct msg_queue *q)
{
	return q->num_msgs;
}

static inline void msg_queue_poll_wait(struct msg_queue *q, struct file *filp, poll_table *p)
{
	poll_wait(filp, &q->rd_wait, p);
	poll_wait(filp, &q->wr_wait, p);
}

static inline void msg_queue_poll_wait_read(struct msg_queue *q, struct file *filp, poll_table *p)
{
	poll_wait(filp, &q->rd_wait, p);
}

static inline void msg_queue_poll_wait_write(struct msg_queue *q, struct file *filp, poll_table *p)
{
	poll_wait(filp, &q->wr_wait, p);
}
#endif /* _MSG_QUEUE_H */
