#ifndef _FAST_SLOB_H
#define _FAST_SLOB_H

#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#define MIN_ALLOC_SIZE		sizeof(char *)
#define MAX_ALLOC_SIZE		(42 * 1024)
#define ALLOC_SIZE_SHIFT	4
#define NUM_BUCKETS		3


struct fast_slob {
	spinlock_t lock;

	char *start;
	size_t size;

	char *buckets[NUM_BUCKETS];
};


static inline struct fast_slob *fast_slob_create(size_t size)
{
	struct fast_slob *slob;
	size_t bucket_size, alloc_size;
	char *start, *buf;
	int i, n;

	bucket_size = size / NUM_BUCKETS;
	alloc_size = MAX_ALLOC_SIZE >> (ALLOC_SIZE_SHIFT * (NUM_BUCKETS - 1));

	if (bucket_size < MAX_ALLOC_SIZE || alloc_size < MIN_ALLOC_SIZE)
		return NULL;

	slob = kmalloc(sizeof(*slob), GFP_KERNEL);
	if (!slob)
		return NULL;

	slob->start = vmalloc_user(size);
	if (!slob->start) {
		kfree(slob);
		return NULL;
	}
	slob->size = size;

	for (i = 0; i < NUM_BUCKETS; i++) {
		start = slob->start + i * bucket_size;
		slob->buckets[i] = start;

		n = 0;
		while (n++ < (bucket_size / alloc_size)) {
			buf = start;
			start += alloc_size;
			*(char **)buf = start;
		}
		*(char **)buf = NULL;

		alloc_size <<= ALLOC_SIZE_SHIFT;
	}

	spin_lock_init(&slob->lock);
	return slob;
}

static inline void fast_slob_destroy(struct fast_slob *slob)
{
	vfree(slob->start);
	kfree(slob);
}

static inline void *fast_slob_alloc(struct fast_slob *slob, size_t size)
{
	size_t alloc_size = MAX_ALLOC_SIZE >> (ALLOC_SIZE_SHIFT * (NUM_BUCKETS - 1));
	char *p;
	int i;

	spin_lock(&slob->lock);
	for (i = 0; i < NUM_BUCKETS; i++) {
		if (alloc_size >= size && slob->buckets[i]) {
			p = slob->buckets[i];
			slob->buckets[i] = *(char **)p;
			spin_unlock(&slob->lock);
			return p;
		}
		alloc_size <<= ALLOC_SIZE_SHIFT;
	}
	spin_unlock(&slob->lock);

	return NULL;
}

static inline void fast_slob_free(struct fast_slob *slob, void *p)
{
	size_t off, idx, alloc_size, bucket_size;

	if ((char *)p < slob->start || (char *)p >= slob->start + slob->size)
		return;
	
	off = (char *)p - slob->start;
	bucket_size = slob->size / NUM_BUCKETS;
	idx = off / bucket_size;
	alloc_size = MAX_ALLOC_SIZE >> (ALLOC_SIZE_SHIFT * (NUM_BUCKETS - 1 - idx));
	if ((off - idx * bucket_size) % alloc_size)
		return;

	spin_lock(&slob->lock);
	*(char **)p = slob->buckets[idx];
	slob->buckets[idx] = p;
	spin_unlock(&slob->lock);
}

#endif	/* _FAST_SLOB_H */
