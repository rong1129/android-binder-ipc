/*
 * msg_queue.c: a generic process messaging queue implementation
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
#include <linux/sched.h>
#include <linux/slab.h>

#include "msg_queue.h"


static DEFINE_SPINLOCK(g_queue_lock);
static struct rb_root g_queue_tree = RB_ROOT;


static inline void rb_insert_queue(struct rb_node *node)
{
	struct rb_node **p = &g_queue_tree.rb_node;
	struct rb_node *parent = NULL;

	while (*p) {
		parent = *p;
		if (node < parent)
			p = &(*p)->rb_left;
		else if (node > p)
			p = &(*p)->rb_right;
		else
			BUG();
	}

	rb_link_node(node, parent, p);
	rb_insert_color(node, &g_queue_tree);
}

static inline int rb_queue_exist(struct msg_queue *q)
{
	struct rb_node *node = &q->rb_node;
	struct rb_node *n = g_queue_tree.rb_node;

	while (n) {
		if (node < n)
			n = n->rb_left;
		else if (node > n)
			n = n->rb_right;
		else
			return 1;
	}

	return 0;
}

struct msg_queue *create_msg_queue(unsigned long max_msgs, msg_release_handler handler)
{
	struct msg_queue *q;

	q = kmalloc(sizeof(*q), GFP_KERNEL); 
	if (!q)
		return NULL;

	q->max_msgs = max_msgs ? max_msgs : DEFAULT_MAX_QUEUE_LENGTH;
	q->num_msgs = 0;

	spin_lock_init(&q->lock);
	INIT_LIST_HEAD(&q->msgs);
	init_waitqueue_head(&q->rd_wait);
	init_waitqueue_head(&q->wr_wait);

	q->release = handler;
	q->active = 1;
	q->usage = 1;

	spin_lock(&g_queue_lock);
	rb_insert_queue(&q->rb_node);
	spin_unlock(&g_queue_lock);
	return q;
}

int free_msg_queue(struct msg_queue *q)
{
	q->active = 0;
	put_msg_queue(q);
}

int get_msg_queue(struct msg_queue *q)
{
	spin_lock(&g_queue_lock);
	if (!rb_queue_exist(q)) {
		spin_unlock(&g_queue_lock);
		return -EFAULT;
	}

	q->usage++;
	spin_unlock(&g_queue_lock);

	return 0;
}

int put_msg_queue(struct msg_queue *q)
{
	spin_lock(&g_queue_lock);

	if (--q->usage > 0) {
		spin_unlock(&g_queue_lock);
		return 0;
	}

	rb_erase(&q->rb_node, &g_queue_tree);
	spin_unlock(&g_queue_lock);

	if (q->release) {
		struct list_head *entry;

		list_for_each_safe(entry, &q->msgs) {
			list_del(entry);
			q->release(entry);
		}
	}

	BUG_ON(waitqueue_active(q->rd_wait) || waitqueue_active(q->wr_wait));
	kfree(q);

	return 1;
}

size_t msg_queue_size(struct msg_queue *q)
{
	size_t size;

	spin_lock(&q->lock);
	size = q->num_msgs;
	spin_unlock(&q->lock);

	return size;
}

static int _write_msg_queue(struct msg_queue *q, struct list_head *msg, int head)
{
	int retval;
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue(&q->wr_wait, &wait);

	do {
		set_current_state(TASK_INTERRUPTIBLE);

		if (!q->active) {
			retval = -EIO;
			break;
		}

		spin_lock(&q->lock);
		if (q->num_msgs < q->max_msgs) {
			if (head)
				list_add_head(msg, &q->msgs);
			else
				list_add_tail(msg, &q->msgs);
			q->num_msgs++;
			spin_unlock(&q->lock);

			wake_up(&q->rd_wait);
			retval = 0;
			break;
		}
		spin_unlock(&q->lock);

		if (signal_pending(current)) {
			retval = -ERESTARTSYS;
			break;
		}
		schedule();
	} while (1);

	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&q->wr_wait, &wait);

	return retval;
}

int write_msg_queue(struct msg_queue *q, struct list_head *msg)
{
	return _write_msg_queue(q, msg, 0);
}

int write_msg_queue_head(struct msg_queue *q, struct list_head *msg)
{
	return _write_msg_queue(q, msg, 1);
}

static int _read_msg_queue(struct msg_queue *q, struct list_head **pmsg, int tail)
{
	int retval;
	struct list_head *entry;
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue(&q->rd_wait, &wait);

	do {
		set_current_state(TASK_INTERRUPTIBLE);

		if (!q->active) {
			retval = -EIO;
			break;
		}

		spin_lock(&q->lock);
		if (!q->num_msgs) {
			if (tail)
				entry = q->msgs->prev;
			else
				entry = q->msgs->next;
	
			list_del(entry);
			q->num_msgs--;
			spin_unlock(&q->lock);

			*pmsg = entry;

			wake_up(&q->wr_wait);
			retval = 0;
			break;
		}
		spin_unlock(&q->lock);

		if (signal_pending(current)) {
			retval = -ERESTARTSYS;
			break;
		}
		schedule();
	} while (1);

	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&q->rd_wait, &wait);

	return retval;
}

int read_msg_queue(struct msg_queue *q, struct list_head **pmsg)
{
	return _read_msg_queue(q, pmsg, 0);
}

int read_msg_queue_tail(struct msg_queue *q, struct list_head **pmsg)
{
	return _read_msg_queue(q, pmsg, 1);
}
