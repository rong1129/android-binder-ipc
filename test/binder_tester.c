#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <signal.h>

#define __USE_GNU
#include <sched.h>


#ifdef INLINE_TRANSACTION_DATA
#define RBUF_SIZE	4096
#else
#define RBUF_SIZE	128
#endif


typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
#include "binder.h"


#define INST_MAX_ENTRIES		32

#define SVC_MAGIC			0x696e7374
#define SVC_BINDER			((void *)SVC_MAGIC)
#define SVC_COOKIE			((void *)SVC_MAGIC)

#define ALIGN(n)        		(((n) + 3) & ~3)


typedef struct binder_write_read bwr_t;
typedef struct flat_binder_object obj_t;
typedef struct binder_transaction_data tdata_t;

typedef struct {
	uint32_t cmd;
	tdata_t tdata;
} bcmd_txn_t;

typedef union {
	struct timeval tv;
	char label[8];
} inst_entry_t;

typedef struct {
	uint32_t magic;
	uint32_t seq;
	uint32_t max_entries;
	uint32_t next_entry;
	inst_entry_t entries[INST_MAX_ENTRIES];
} inst_buf_t;


uint16_t svcmgr_id[] = { 'a','n','d','r','o','i','d','.','o','s','.',
			 'I','S','e','r','v','i','c','e','M','a','n','a','g','e','r' };
static uint16_t service[] = { 'i', 'n', 's', 't' };

static int clients = 1;
static int time_ref = 1;
static int inst_kernel = 1;
static int share_cpus = 1;
static int iterations = 1000;
static char *output_file;
static int id;

static unsigned int ioctl_read, ioctl_write, ioctl_buffer;


void hexdump(const void *buf, unsigned long size)
{
	int col = 0, off = 0;
	unsigned char *p = (unsigned char *)buf;

	while (size--) {
		if (!col)
			printf("\t%08x:", off);

		printf(" %02x", *p++);

		off++;
		col++;

		if (!(col % 16)) {
			printf("\n");
			col = 0;
		} else if (!(col % 4))
			printf("  ");
	}

	if (col % 16)
		printf("\n\n");
	else
		printf("\n");
}

inline void INST_INIT(inst_buf_t *inst)
{
	inst->magic = inst_kernel ? SVC_MAGIC : ~SVC_MAGIC;
	inst->seq = 0;
	inst->max_entries = INST_MAX_ENTRIES;
}

inline void INST_BEGIN(inst_buf_t *inst)
{
	inst->next_entry = 0;
}

inline void INST_RECORD(inst_entry_t *entry)
{
	gettimeofday(&entry->tv, NULL);
}

inline void INST_ENTRY_COPY(inst_buf_t *inst, char *label, inst_entry_t *copy)
{
	if (inst->next_entry < inst->max_entries) {
		inst_entry_t *entry = inst->entries + inst->next_entry++;

		if (inst->seq)
			*entry = *copy;
		else {
			strncpy(entry->label, label, 8);
			entry->label[7] = '\0';
		}
	}
}

inline void INST_ENTRY(inst_buf_t *inst, char *label)
{
	inst_entry_t copy;

	gettimeofday(&copy.tv, NULL);
	INST_ENTRY_COPY(inst, label, &copy);
}

inline void INST_END(inst_buf_t *inst, unsigned char **buf)
{
	if (buf) {
		int size = inst->next_entry * sizeof(inst_entry_t);

		memcpy(*buf, inst->entries, size);
		*buf += size;
	}
	inst->seq++;
}

bcmd_txn_t *create_transaction(int reply,
			       void *binder, void *cookie, unsigned int code,
			       unsigned char *data, unsigned int data_size, unsigned char *offsets, unsigned int offsets_size)
{
	bcmd_txn_t *txn;
	tdata_t *tdata;
	unsigned char *p;
	unsigned int size, data_off = 0, offsets_off = 0;

	size = ALIGN(sizeof(*txn));
	if (data_size > 0) {
		data_off = size;
		size += ALIGN(data_size);

		if (offsets_size > 0) {
			offsets_off = size;
			size += ALIGN(offsets_size);
		}
	}

	p = malloc(size);
	if (!p)
		return NULL;

	txn = (bcmd_txn_t *)p;
	txn->cmd = reply ? BC_REPLY : BC_TRANSACTION;
	
	tdata = &txn->tdata;
	memset(tdata, 0, sizeof(*tdata));
	tdata->target.ptr = binder;
	tdata->cookie = cookie;
	tdata->code = code;
	
	if (data_size > 0) {
		if (data)
			memcpy(p + data_off, data, data_size);
		tdata->data.ptr.buffer = p + data_off;
		tdata->data_size = data_size;

		if (offsets_size > 0) {
			if (offsets)
				memcpy(p + offsets_off, offsets, offsets_size);
			tdata->data.ptr.offsets = p + offsets_off;
			tdata->offsets_size = offsets_size;
		}
	}

	return txn;
}

#if (defined(SIMULATE_FREE_BUFFER) || !defined(INLINE_TRANSACTION_DATA))
int FREE_BUFFER(int fd, void *ptr)
{
	bwr_t bwr;
	uint32_t cmd[2];

	cmd[0] = BC_FREE_BUFFER;
	cmd[1] = (uint32_t)ptr;

	memset(&bwr, 0, sizeof(bwr));
	bwr.write_buffer = (unsigned long)cmd;
	bwr.write_size = sizeof(cmd);

	ioctl_buffer++;
	return ioctl(fd, BINDER_WRITE_READ, &bwr);
}
#endif

int parse_command(void *buf, unsigned long size, tdata_t **reply)
{
	unsigned char *p, *ep;
	unsigned int cmd;
	tdata_t *tdata = NULL;
#ifdef INLINE_TRANSACTION_DATA
	unsigned long buffer_size;
#endif

	p = buf;
	ep = p + size;
	while (p < ep) {
		cmd = *(unsigned int *)p;
		p += sizeof(cmd);

		switch (cmd) {
			case BR_NOOP:
			case BR_TRANSACTION_COMPLETE:
				break;

			case BR_INCREFS:
			case BR_ACQUIRE:
			case BR_RELEASE:
			case BR_DECREFS:
				if (p + 2 * sizeof(cmd) > ep) {
					fprintf(stderr, "not enough ref_cmd data\n");
					return -1;
				}
				p += 2 * sizeof(cmd);
				break;

			case BR_TRANSACTION:
				fprintf(stderr, "rcv transaction\n");
				if (p + sizeof(*tdata) > ep) {
					fprintf(stderr, "not enough transaction data\n");
					return -1;
				}

				tdata = (tdata_t *)p;
				p += sizeof(*tdata);
#ifdef INLINE_TRANSACTION_DATA
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "not enough transaction data buffer\n");
					return -1;
				}
				p += buffer_size;
#endif
				tdata = NULL;
				break;

			case BR_REPLY:
				if (p + sizeof(*tdata) > ep) {
					fprintf(stderr, "not enough transaction data\n");
					return -1;
				}

				tdata = (tdata_t *)p;
				p += sizeof(*tdata);
#ifdef INLINE_TRANSACTION_DATA
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "not enough transaction data buffer\n");
					return -1;
				}
				p += buffer_size;
#endif
				goto expected_out;

			case BR_DEAD_BINDER:
				fprintf(stderr, "rcv DEAD_BINDER\n");
				if (p + sizeof(cmd) > ep) {
					fprintf(stderr, "not enough dead binder data\n");
					return -1;
				}

				p += sizeof(cmd);
				break;

			case BR_FAILED_REPLY:
				fprintf(stderr, "rcv FAILED_BINDER\n");
				return -1;

			case BR_DEAD_REPLY:
				fprintf(stderr, "rcv DEAD_BINDER\n");
				return -1;

			default:
				fprintf(stderr, "rcv unknown command: %u\n", cmd);
				return -1;
		}
	}

expected_out:
	*reply = tdata;
	return p - (unsigned char *)buf;
}

int simple_transact(int fd, bcmd_txn_t *txn, tdata_t **preply, unsigned char *buf, unsigned int size)
{
	bwr_t bwr;
	tdata_t *reply = NULL;
	int r, retries = 2;

	bwr.write_buffer = (unsigned long)txn;
	bwr.write_size = sizeof(*txn);
	bwr.write_consumed = 0;

wait_reply:
	bwr.read_buffer = (unsigned long)buf;
	bwr.read_size = size;
	bwr.read_consumed = 0;

	r = ioctl(fd, BINDER_WRITE_READ, &bwr);
	if (r < 0)
		return r;

	if (bwr.read_consumed > 0) {
		r = parse_command(buf, bwr.read_consumed, &reply);
		if (r < 0)
			return r;
	}

	if (reply) {
		*preply = reply;
		return 0;
	}

	if (retries-- <= 0) {
		fprintf(stderr, "no reply received\n");
		return -1;
	}

	bwr.write_size = 0;
	goto wait_reply;
}

int add_service(int fd, void *binder, void *cookie, uint16_t *name, int len)
{
	unsigned char buf[1024], *p;
	obj_t *obj;
	size_t *offsets;
	bcmd_txn_t *txn;
	tdata_t *tdata;
	int r;

	p = buf;

	// strict_policy
	*(uint32_t *)p = 0;
	p += 4;

	// svcmgr_id 
	*(uint32_t *)p = sizeof(svcmgr_id) / 2;
	p += 4;
	memcpy(p, svcmgr_id, sizeof(svcmgr_id));
	p += sizeof(svcmgr_id);
	*(uint16_t *)p = 0;
	p += 2;
	p = (unsigned char *)ALIGN((unsigned long)p);
	
	// name 
	*(uint32_t *)p = len;
	p += 4;
	memcpy(p, name, len * 2);
	p += len * 2;
	*(uint16_t *)p = 0;
	p += 2;
	p = (unsigned char *)ALIGN((unsigned long)p);

	// flat_binder_obj
	obj = (obj_t *)p;
	obj->type = BINDER_TYPE_BINDER;
	obj->flags = 0;
	obj->binder = binder;
	obj->cookie = cookie;
	p = (unsigned char *)(obj + 1);

	// offsets
	offsets = (size_t *)p;
	*offsets = (unsigned char *)obj - buf;

	txn = create_transaction(0, NULL, NULL, 3, buf, p - buf, (unsigned char *)offsets, 4);
	if (!txn)
		return -1;

	r = simple_transact(fd, txn, &tdata, buf, sizeof(buf));
	if (r < 0)
		return r;

	if (tdata->data_size != 4 || *(unsigned int *)tdata->data.ptr.buffer) {
		fprintf(stderr, "server invalid reply data received\n");
		return -1;
	}

#if (defined(SIMULATE_FREE_BUFFER) || !defined(INLINE_TRANSACTION_DATA))
	if (FREE_BUFFER(fd, (void *)tdata->data.ptr.buffer) < 0) {
		fprintf(stderr, "failed to free shared buffer\n");
		return -1;
	}
#endif
	free(txn);
	return 0;
}

int start_looper(int fd)
{
	bwr_t bwr;
	uint32_t cmd[1];

	cmd[0] = BC_ENTER_LOOPER;

	memset(&bwr, 0, sizeof(bwr));
	bwr.write_buffer = (unsigned long)cmd;
	bwr.write_size = sizeof(cmd);

	return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

int lookup_service(int fd, uint16_t *name, int len, void **binder, void **cookie)
{
	unsigned char buf[1024], *p;
	obj_t *obj;
	bcmd_txn_t *txn;
	tdata_t *tdata;
	int r;

	p = buf;

	// strict_policy
	*(uint32_t *)p = 0;
	p += 4;

	// svcmgr_id 
	*(uint32_t *)p = sizeof(svcmgr_id) / 2;
	p += 4;
	memcpy(p, svcmgr_id, sizeof(svcmgr_id));
	p += sizeof(svcmgr_id);
	*(uint16_t *)p = 0;
	p += 2;
	p = (unsigned char *)ALIGN((unsigned long)p);
	
	// name 
	*(uint32_t *)p = len;
	p += 4;
	memcpy(p, name, len * 2);
	p += len * 2;
	*(uint16_t *)p = 0;
	p += 2;
	p = (unsigned char *)ALIGN((unsigned long)p);

	txn = create_transaction(0, NULL, NULL, 1, buf, p - buf, NULL, 0);
	if (!txn)
		return -1;

	r = simple_transact(fd, txn, &tdata, buf, sizeof(buf));
	if (r < 0)
		return r;

	if (tdata->data_size == 4 && !*(unsigned int *)tdata->data.ptr.buffer)
		return 0;	// server not ready

	if (tdata->data_size != sizeof(*obj) || tdata->offsets_size != 4) {
		fprintf(stderr, "client %d invalid reply data received\n", id);
		return -1;
	}
	obj = (obj_t *)((unsigned char *)tdata->data.ptr.buffer + *(unsigned int *)tdata->data.ptr.offsets);
	if (obj->type != BINDER_TYPE_HANDLE) {
		fprintf(stderr, "client %d invalid object type received\n", id);
		return -1;
	}
	*binder = obj->binder;
	*cookie = obj->cookie;

	free(txn);
	return 1;
}

int server_parse_command(unsigned char *buf, long size, tdata_t **tdata_out, bcmd_txn_t **txn_out)
{
	unsigned char *p, *ep;
	unsigned int cmd;
	tdata_t *tdata = NULL;
	bcmd_txn_t *txn = NULL;
#ifdef INLINE_TRANSACTION_DATA
	unsigned long buffer_size;
#endif

	p = buf;
	ep = p + size;
	while (p < ep) {
		cmd = *(unsigned int *)p;
		p += sizeof(cmd);

		switch (cmd) {
			case BR_NOOP:
			case BR_TRANSACTION_COMPLETE:
				break;

			case BR_INCREFS:
			case BR_ACQUIRE:
			case BR_RELEASE:
			case BR_DECREFS:
				fprintf(stderr, "server received unexpected ref_cmd command\n");
				if (p + 2 * sizeof(cmd) > ep) {
					fprintf(stderr, "server not enough ref_cmd data\n");
					return -1;
				}
				p += 2 * sizeof(cmd);
				break;

			case BR_TRANSACTION:
				if (p + sizeof(*tdata) > ep) {
					fprintf(stderr, "server not enough transaction data\n");
					return -1;
				}

				tdata = (tdata_t *)p;
				p += sizeof(*tdata);

				if (tdata->data_size != sizeof(inst_buf_t)) {
					fprintf(stderr, "server data size in transaction is incorrect\n");
					return -1;
				}

#ifdef INLINE_TRANSACTION_DATA
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "server not enough transaction data buffer\n");
					return -1;
				}

				txn = (bcmd_txn_t *)(p - sizeof(*tdata) - sizeof(cmd));
				txn->cmd = BC_REPLY;

				p += buffer_size;
#else
				txn = create_transaction(1, NULL, NULL, 0,
							(unsigned char *)tdata->data.ptr.buffer, tdata->data_size, 
							(unsigned char *)tdata->data.ptr.offsets, tdata->offsets_size);
				if (!txn) {
					fprintf(stderr, "server failed to create reply buffer\n");
					return -1;
				}
#endif

				goto expected_out;

			case BR_REPLY:
				fprintf(stderr, "server received unexpected reply command\n");
				if (p + sizeof(*tdata) > ep) {
					fprintf(stderr, "server not enough transaction data\n");
					return -1;
				}

				tdata = (tdata_t *)p;
				p += sizeof(*tdata);

#ifdef INLINE_TRANSACTION_DATA
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "server not enough transaction data buffer\n");
					return -1;
				}
				p += buffer_size;
#endif
				break;

			case BR_DEAD_BINDER:
				fprintf(stderr, "server received unexpected dead_binder command\n");
				if (p + sizeof(cmd) > ep) {
					fprintf(stderr, "server not enough dead binder data\n");
					return -1;
				}

				p += sizeof(cmd);
				break;

			case BR_FAILED_REPLY:
				fprintf(stderr, "server received unexpected failed_reply command\n");
				return -1;

			case BR_DEAD_REPLY:
				fprintf(stderr, "server received unexpected dead_reply command\n");
				return -1;

			default:
				fprintf(stderr, "server received unknown command\n");
				return -1;
		}
	}

expected_out:
	*tdata_out = tdata;
	*txn_out = txn;
	return (p - buf);
}

int server_main(void)
{
	int fd, r, len;
	void *binder, *cookie;
	bwr_t bwr;
	unsigned char rbuf[RBUF_SIZE], *p;
	bcmd_txn_t *reply;
	tdata_t *tdata = NULL;
	inst_buf_t *inst;
	inst_entry_t copy;

	if (!share_cpus) {
		cpu_set_t cpuset;

		CPU_ZERO(&cpuset);
		CPU_SET(0, &cpuset);
		r = sched_setaffinity(0, sizeof(cpuset), &cpuset);
		if (!r)
			printf("server is bound to CPU 0\n");
		else
			fprintf(stderr, "server failed to be bound to CPU 0\n");
	}

	fd = open("/dev/binder", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "failed to open binder device\n");
		return -1;
	}

#if (!defined(INLINE_TRANSACTION_DATA))
	if (mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED) {
		fprintf(stderr, "server failed to mmap shared buffer\n");
		return -1;
	}
#endif

	binder = SVC_BINDER;
	cookie = SVC_COOKIE;

	r = add_service(fd, binder, cookie, service, sizeof(service) / 2);
	if (r < 0) {
		printf("server failed to add instrumentation service\n");
		return -1;
	}
	printf("server added instrumentation service\n");

	r = start_looper(fd);
	if (r < 0) {
		printf("server failed to start looper\n");
		return -1;
	}
	
	bwr.read_buffer = (unsigned long)rbuf;
	while (1) {
		bwr.read_size = sizeof(rbuf);
		bwr.read_consumed = 0;
		bwr.write_size = 0;

		ioctl_read++;
		r = ioctl(fd, BINDER_WRITE_READ, &bwr);
		if (r < 0) {
			fprintf(stderr, "server failed ioctl\n");
			return r;
		}
		INST_RECORD(&copy);

		p = rbuf;
		len = bwr.read_consumed;
		while (len > 0) {
			r = server_parse_command(p, len, &tdata, &reply);
			if (r < 0)
				return r;

			p += r;
			len -= r;

#if (defined(SIMULATE_FREE_BUFFER) || !defined(INLINE_TRANSACTION_DATA))
			if (tdata) 
				FREE_BUFFER(fd, (void *)tdata->data.ptr.buffer);
#endif
			if (!reply) {
				//hexdump(rbuf, bwr.read_consumed);
				continue;
			}

			inst = (inst_buf_t *)reply->tdata.data.ptr.buffer;
			INST_ENTRY_COPY(inst, "S_RECV", &copy);

			bwr.write_buffer = (unsigned long)reply;
			bwr.write_size = sizeof(*reply);
			bwr.write_consumed = 0;
			bwr.read_size = 0;

			INST_ENTRY(inst, "S_REPLY");

			ioctl_write++;
			r = ioctl(fd, BINDER_WRITE_READ, &bwr);
			if (r < 0) {
				fprintf(stderr, "server failed reply ioctl\n");
				return r;
			}

#if (!defined(INLINE_TRANSACTION_DATA))
			free(reply);
#endif
		}
	}

	free(reply);
	return 0;
}

int client_parse_command(int id, unsigned char *buf, unsigned long size, inst_buf_t **pinst)
{
	unsigned char *p, *ep;
	unsigned int cmd;
	tdata_t *tdata;
	inst_buf_t *inst = NULL;
#ifdef INLINE_TRANSACTION_DATA
	unsigned long buffer_size;
#endif

	p = buf;
	ep = p + size;
	while (p < ep) {
		cmd = *(unsigned int *)p;
		p += sizeof(cmd);

		switch (cmd) {
			case BR_NOOP:
			case BR_TRANSACTION_COMPLETE:
				break;

			case BR_INCREFS:
			case BR_ACQUIRE:
			case BR_RELEASE:
			case BR_DECREFS:
				fprintf(stderr, "client %d received unexpected ref_cmd command\n", id);
				if (p + 2 * sizeof(cmd) > ep) {
					fprintf(stderr, "client %d not enough ref_cmd data\n", id);
					return -1;
				}
				p += 2 * sizeof(cmd);
				break;

			case BR_TRANSACTION:
				fprintf(stderr, "client %d received unexpected transaction command\n", id);
				if (p + sizeof(*tdata) > ep) {
					fprintf(stderr, "client %d: not enough transaction data\n", id);
					return -1;
				}

				tdata = (tdata_t *)p;
				p += sizeof(*tdata);
#ifdef INLINE_TRANSACTION_DATA
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "client %d: not enough transaction data buffer\n", id);
					return -1;
				}
				p += buffer_size;
#endif
				break;

			case BR_REPLY:
				if (p + sizeof(*tdata) > ep) {
					fprintf(stderr, "client %d: not enough transaction data\n", id);
					return -1;
				}

				tdata = (tdata_t *)p;
				p += sizeof(*tdata);
#ifdef INLINE_TRANSACTION_DATA
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "client %d: not enough transaction data buffer\n", id);
					return -1;
				}
				p += buffer_size;
#endif

				if (tdata->data_size != sizeof(inst_buf_t)) {
					fprintf(stderr, "client %d: data size in reply is incorrect\n", id);
					return -1;
				}
				if (inst) {
					fprintf(stderr, "client %d: received multiple reply\n", id);
					return -1;
				}
				inst = (inst_buf_t *)tdata->data.ptr.buffer;
				break;

			case BR_DEAD_BINDER:
				fprintf(stderr, "client %d received unexpected dead_binder command\n", id);
				if (p + sizeof(cmd) > ep) {
					fprintf(stderr, "client %d: not enough dead binder data\n", id);
					return -1;
				}

				p += sizeof(cmd);
				break;

			case BR_FAILED_REPLY:
				fprintf(stderr, "client %d received unexpected failed_reply command\n", id);
				return -1;

			case BR_DEAD_REPLY:
				fprintf(stderr, "client %d received unexpected dead_reply command\n", id);
				return -1;

			default:
				fprintf(stderr, "client %d received unknown command\n", id);
				return -1;
		}
	}

	if (p != ep) {
		fprintf(stderr, "client %d receiver buffer has unknown data\n", id);
		return -1;
	}

	*pinst = inst;
	return 0;
}

int client_main(void)
{
	int fd, r, n, m, wait = 0, retries;
	void *binder, *cookie;
	bcmd_txn_t *txn;
	bwr_t bwr;
	inst_buf_t *inst, *inst_reply;
	inst_entry_t *entry, copy;
	unsigned char rbuf[RBUF_SIZE], *ibuf, *p;
	struct timeval ref, delta;
	FILE *fp;

	if (!share_cpus) {
		cpu_set_t cpuset;

		CPU_ZERO(&cpuset);
		CPU_SET(id + 1, &cpuset);
		r = sched_setaffinity(0, sizeof(cpuset), &cpuset);
		if (!r)
			printf("client %d is bound to CPU %d\n", id, id + 1);
		else
			fprintf(stderr, "client %d failed to be bound to CPU %d\n", id, id + 1);
	}

	fd = open("/dev/binder", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "client %d failed to open binder device\n", id);
		return -1;
	}

#if (!defined(INLINE_TRANSACTION_DATA))
	if (mmap(NULL, 128 * 1024, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED) {
		fprintf(stderr, "server failed to mmap shared buffer\n");
		return -1;
	}
#endif

	while (1) {
		r = lookup_service(fd, service, sizeof(service) / 2, &binder, &cookie);
		if (r < 0) {
			fprintf(stderr, "client %d failed to find the instrumentation service\n", id);
			return -1;
		} else if (r > 0)
			break;

		if (wait++ > 1)
			fprintf(stderr, "client %d still waiting on instrumentation service to be ready\n", id);
		sleep(1);
	}
	printf("client %d found instrumentation service\n", id);

	txn = create_transaction(0, binder, cookie, 0, NULL, sizeof(inst_buf_t), NULL, 0);
	if (!txn) {
		fprintf(stderr, "client %d failed to prepare transaction buffer\n", id);
		return -1;
	}

	bwr.write_buffer = (unsigned long)txn;
	bwr.read_buffer = (unsigned long)rbuf;

	inst = (inst_buf_t *)txn->tdata.data.ptr.buffer;
	INST_INIT(inst);

	ibuf = malloc((iterations + 1) * sizeof(inst_entry_t) * INST_MAX_ENTRIES);
	if (!ibuf)
		fprintf(stderr, "client %d failed to allocate instrumentation buffer\n", id);

	p = ibuf;
	n = iterations + 1;
	while (n-- > 0) {
		INST_BEGIN(inst);

		retries = 2;

		bwr.write_size = sizeof(*txn);
		bwr.write_consumed = 0;
		bwr.read_size = sizeof(rbuf);
		bwr.read_consumed = 0;

		INST_ENTRY(inst, "C_SEND");

		ioctl_write++;
wait_reply:
		ioctl_read++;
		r = ioctl(fd, BINDER_WRITE_READ, &bwr);
		if (r < 0) {
			fprintf(stderr, "client %d failed ioctl\n", id);
			return r;
		}
		INST_RECORD(&copy);

		r = client_parse_command(id, rbuf, bwr.read_consumed, &inst_reply);
		if (r < 0)
			return r;

		if (!inst_reply) {
			//hexdump(rbuf, bwr.read_consumed);
			if (retries-- > 0) {
				bwr.write_size = 0;
				bwr.read_consumed = 0;
				goto wait_reply;
			} else {
				fprintf(stderr, "client %d failed to receive reply\n", id);
				return -1;
			}
		}

		memcpy(inst, inst_reply, sizeof(*inst));

		INST_ENTRY_COPY(inst, "C_RECV", &copy);
		INST_END(inst, &p);

#if (defined(SIMULATE_FREE_BUFFER) || !defined(INLINE_TRANSACTION_DATA))
		if (FREE_BUFFER(fd, inst_reply) < 0) {
			fprintf(stderr, "client %d: failed to free shared buffer\n", id);
			return -1;
		}
#endif
	}

	if (output_file) {
		if (clients > 1) {
			char *p = malloc(strlen(output_file) + 16);

			if (!p) {
				fprintf(stderr, "client %d failed to alloc memory for filename\n", id);
				return -1;
			}
			sprintf(p, "%s-%d", output_file, id);
			output_file = p;
		}

		fp = fopen(output_file, "w");
		if (!fp) {
			fprintf(stderr, "client %d failed to open dump file\n", id);
			return -1;
		}
	} else
		fp = stdout;

	entry = (inst_entry_t *)ibuf;
	for (n = 0; n < inst->seq; n++) {
		for (m = 0; m < inst->next_entry; m++) {
			if (n > 0) {
				if (m == 0) {
					if (time_ref == 0)	// absolute time
						ref.tv_sec = ref.tv_usec = 0;
					else 
						ref = entry->tv;
				}

				delta.tv_sec = entry->tv.tv_sec - ref.tv_sec;
				delta.tv_usec = entry->tv.tv_usec - ref.tv_usec;
				if (delta.tv_usec < 0) {
					delta.tv_sec--;
					delta.tv_usec += 1000000;
				}

				fprintf(fp, "%ld.%06ld\t", delta.tv_sec, delta.tv_usec);

				if (time_ref > 1)	// relative to the previous entry
					ref = entry->tv;
			} else
				fprintf(fp, "%8s\t", entry->label);

			entry++;
		}
		fprintf(fp, "\n");
	}

	if (fp != stdout)
		fclose(fp);
	free(txn);

	printf("client %d: ioctl read: %u\n", id, ioctl_read);
	printf("client %d: ioctl write: %u\n", id, ioctl_write);
	printf("client %d: ioctl buffer: %u\n", id, ioctl_buffer);
	return 0;
}

void children_reaper(int sig)
{
	pid_t pid;
	int stat;

	do {
		pid = waitpid((pid_t)-1, &stat, WNOHANG | WUNTRACED);
	} while (pid > 0);

	if (pid >= 0)	// more children
		return;

	printf("server: ioctl read: %u\n", ioctl_read);
	printf("server: ioctl write: %u\n", ioctl_write);
	printf("server: ioctl buffer: %u\n", ioctl_buffer);
	exit(0);
}

int main(int argc, char **argv)
{
	int i, c;
	pid_t pid;

	while ((c = getopt(argc, argv, "hKSc:n:o:t:")) != -1) {
		switch (c) {
			case 'K':
				inst_kernel = 0;
				break;
			case 'S':
				share_cpus = 0;
				break;
			case 'c':
				clients = atoi(optarg);
				if (clients < 1)
					clients = 1;
				break;
			case 'n':
				iterations = atoi(optarg);
				if (iterations < 1)
					iterations = 1;
				break;
			case 'o':
				output_file = strdup(optarg);
				break;
			case 't':
				time_ref = atoi(optarg);
				if (time_ref < 0 || time_ref > 2)
					time_ref = 1;
				break;
			default:
				fprintf(stderr, "Usage: binder_test [-hKS] [-c <clients>]\n"
						"                   [-n <iterations>]\n"
						"                   [-o <output file>]\n"
						"                   [-t <0: absolute | 1: relative-to-first | 2: relative-to-previous]\n");
				exit(1);
		}
	}

	for (i = 0; i < clients; i++) {
		pid = fork();

		if (!pid) {
			id = i;
			client_main();
			exit(0);
		} else if (pid < 0) {
			fprintf(stderr, "server fork error\n");
			return -1;
		}
	}

	signal(SIGCHLD, children_reaper);
	server_main();
	return 0;
}
