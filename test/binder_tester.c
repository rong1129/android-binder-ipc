#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/wait.h>


typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
#include "binder.h"


#define INSTRUCTING_MAX_ENTRIES		32

#define SVC_BINDER			(void *)0x696e7374
#define SVC_COOKIE			(void *)~((unsigned long)SVC_BINDER)

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
	uint32_t seq;
	uint32_t max_entries;
	uint32_t next_entry;
	inst_entry_t entries[INSTRUCTING_MAX_ENTRIES];
} inst_buf_t;


uint16_t svcmgr_id[] = { 'a','n','d','r','o','i','d','.','o','s','.',
			 'I','S','e','r','v','i','c','e','M','a','n','a','g','e','r' };
static uint16_t service[] = { 'i', 'n', 's', 't' };

static int iterations = 1;
static char *output_file;


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
	inst->seq = 0;
	inst->max_entries = INSTRUCTING_MAX_ENTRIES;
}

inline void INST_START(inst_buf_t *inst)
{
	inst->next_entry = 0;
}

inline void INST_RECORD(inst_entry_t *entry)
{
	gettimeofday(&entry->tv, NULL);
}

inline void INST_ENTRY(inst_buf_t *inst, char *label)
{
	inst_entry_t copy;

	gettimeofday(&copy.tv, NULL);

	if (inst->next_entry < inst->max_entries) {
		inst_entry_t *entry = inst->entries + inst->next_entry++;

		if (inst->seq)
			*entry = copy;
		else
			strncpy(entry->label, label, 8);
	}
}

inline void INST_ENTRY_COPY(inst_buf_t *inst, char *label, inst_entry_t *copy)
{
	if (inst->next_entry < inst->max_entries) {
		inst_entry_t *entry = inst->entries + inst->next_entry++;

		*entry = *copy;
	}
}

inline void INST_END(inst_buf_t *inst, unsigned char *buf)
{
	memcpy(buf, inst->entries, inst->next_entry * 8);
	inst->seq++;
}

int parse_command(void *buf, unsigned long size, bcmd_txn_t **reply)
{
	unsigned char *p, *ep;
	unsigned int cmd;
	bcmd_txn_t *txn = NULL;
	tdata_t *tdata;
	unsigned long buffer_size;

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
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "not enough transaction data buffer\n");
					return -1;
				}
				p += buffer_size;
				break;

			case BR_REPLY:
				if (p + sizeof(*tdata) > ep) {
					fprintf(stderr, "not enough transaction data\n");
					return -1;
				}

				tdata = (tdata_t *)p;

				p += sizeof(*tdata);
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "not enough transaction data buffer\n");
					return -1;
				}
				txn = (bcmd_txn_t *)(p - sizeof(*tdata) - sizeof(cmd));
				p += buffer_size;
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
	*reply = txn;
	return p - (unsigned char *)buf;
}

int simple_transact(int fd, bcmd_txn_t *txn, bcmd_txn_t **preply, unsigned char *buf, unsigned int size)
{
	bwr_t bwr;
	bcmd_txn_t *reply = NULL;
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

int add_service(int fd, void *binder, void *cookie, uint16_t *name, int len)
{
	unsigned char buf[1024], *p;
	obj_t *obj;
	size_t *offsets;
	bcmd_txn_t *txn, *reply;
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

	r = simple_transact(fd, txn, &reply, buf, sizeof(buf));
	if (r < 0)
		return r;

	tdata = &reply->tdata;
	if (tdata->data_size != 4 || *(unsigned int *)tdata->data.ptr.buffer) {
		fprintf(stderr, "invalid reply data received\n");
		return -1;
	}

	free(txn);
	return 0;
}

int lookup_service(int fd, uint16_t *name, int len, void **binder, void **cookie)
{
	unsigned char buf[1024], *p;
	obj_t *obj;
	bcmd_txn_t *txn, *reply;
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

	r = simple_transact(fd, txn, &reply, buf, sizeof(buf));
	if (r < 0)
		return r;

	tdata = &reply->tdata;
	if (tdata->data_size == 4 && *(unsigned int *)tdata->data.ptr.buffer)
		return 0;	// server not ready

	if (tdata->data_size != sizeof(*obj) || tdata->offsets_size != 4) {
		fprintf(stderr, "invalid reply data received\n");
		return -1;
	}
	obj = (obj_t *)((unsigned char *)tdata->data.ptr.buffer + *(unsigned int *)tdata->data.ptr.offsets);
	if (obj->type != BINDER_TYPE_HANDLE) {
		fprintf(stderr, "invalid object type received\n");
		return -1;
	}
	*binder = obj->binder;
	*cookie = obj->cookie;

	free(txn);
	return 1;
}

int server_parse_command(unsigned char *buf, long *psize, bcmd_txn_t **txn_out)
{
	unsigned char *p, *ep;
	unsigned int cmd;
	bcmd_txn_t *txn = NULL;
	tdata_t *tdata;
	unsigned long buffer_size;

	p = buf;
	ep = p + *psize;
	while (p < ep) {
		cmd = *(unsigned int *)p;
		p += sizeof(cmd);

		switch (cmd) {
			case BR_TRANSACTION_COMPLETE:
				break;

			case BR_NOOP:
				fprintf(stderr, "server received unexpected noop command\n");
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
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "server not enough transaction data buffer\n");
					return -1;
				}

				if (tdata->data_size != sizeof(inst_buf_t)) {
					fprintf(stderr, "server data size in transaction is incorrect\n");
					return -1;
				}
				txn = (bcmd_txn_t *)(p - sizeof(*tdata) - sizeof(cmd));
				p += buffer_size;

				goto expected_out;

			case BR_REPLY:
				fprintf(stderr, "server received unexpected reply command\n");
				if (p + sizeof(*tdata) > ep) {
					fprintf(stderr, "server not enough transaction data\n");
					return -1;
				}

				tdata = (tdata_t *)p;

				p += sizeof(*tdata);
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "server not enough transaction data buffer\n");
					return -1;
				}
				p += buffer_size;
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
	*psize -= (p - buf);
	*txn_out = txn;
	return 0;
}

int server_main(void)
{
	int fd, r;
	void *binder, *cookie;
	bwr_t bwr;
	unsigned char rbuf[4096];
	bcmd_txn_t *txn;
	inst_buf_t *inst;
	inst_entry_t entry;

	fd = open("/dev/binder", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "failed to open binder device\n");
		return -1;
	}

	binder = SVC_BINDER;
	cookie = SVC_COOKIE;

	r = add_service(fd, binder, cookie, service, sizeof(service) / 2);
	if (r < 0) {
		printf("server failed to add instrumenting service\n");
		return -1;
	}
	printf("server added instrumenting service\n");

	bwr.read_buffer = (unsigned long)rbuf;

	while (1) {
		bwr.read_size = sizeof(rbuf);
		bwr.read_consumed = 0;
		bwr.write_size = 0;

		r = ioctl(fd, BINDER_WRITE_READ, &bwr);
		if (r < 0) {
			fprintf(stderr, "server failed ioctl\n");
			return r;
		}
		INST_RECORD(&entry);

		while (bwr.read_consumed > 0) {
			r = server_parse_command(rbuf, &bwr.read_consumed, &txn);
			if (r < 0)
				return r;
			if (!txn)
				continue;

			txn->cmd = BC_REPLY;
			inst = (inst_buf_t *)txn->tdata.data.ptr.buffer;
			INST_ENTRY_COPY(inst, "S_RECV", &entry);

			bwr.write_buffer = (unsigned long)txn;
			bwr.write_size = sizeof(*txn);
			bwr.write_consumed = 0;
			bwr.read_size = 0;

			INST_ENTRY(inst, "S_REPLY");

			r = ioctl(fd, BINDER_WRITE_READ, &bwr);
			if (r < 0) {
				fprintf(stderr, "server failed reply ioctl\n");
				return r;
			}
		}
	}

	free(txn);
	return 0;
}

int client_parse_command(int id, unsigned char *buf, unsigned long size, inst_buf_t **pinst)
{
	unsigned char *p, *ep;
	unsigned int cmd;
	tdata_t *tdata;
	inst_buf_t *inst = NULL;
	unsigned long buffer_size;

	p = buf;
	ep = p + size;
	while (p < ep) {
		cmd = *(unsigned int *)p;
		p += sizeof(cmd);

		switch (cmd) {
			case BR_TRANSACTION_COMPLETE:
				break;

			case BR_NOOP:
				fprintf(stderr, "client %d received unexpected noop command\n", id);
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
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "client %d: not enough transaction data buffer\n", id);
					return -1;
				}
				p += buffer_size;
				break;

			case BR_REPLY:
				if (p + sizeof(*tdata) > ep) {
					fprintf(stderr, "client %d: not enough transaction data\n", id);
					return -1;
				}

				tdata = (tdata_t *)p;

				p += sizeof(*tdata);
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "client %d: not enough transaction data buffer\n", id);
					return -1;
				}
				p += buffer_size;

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

	return 0;
}

int client_main(int id)
{
	int fd, r, n, m, wait = 0, retries;
	void *binder, *cookie;
	bcmd_txn_t *txn;
	bwr_t bwr;
	inst_buf_t *inst;
	inst_entry_t *entry, copy;
	unsigned char rbuf[4096], *ibuf, *p;
	FILE *fp;

	fd = open("/dev/binder", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "client %d failed to open binder device\n", id);
		return -1;
	}

	while (1) {
		r = lookup_service(fd, service, sizeof(service) / 2, &binder, &cookie);
		if (r < 0) {
			fprintf(stderr, "client %d failed to find the instrumenting service\n", id);
			return -1;
		} else if (r > 0)
			break;

		if (wait++ > 1)
			fprintf(stderr, "client %d still waiting on instrumenting service to be ready\n", id);
		sleep(1);
	}
	printf("client %d found instrumenting service\n", id);

	txn = create_transaction(0, binder, cookie, 0, NULL, sizeof(inst_buf_t), NULL, 0);
	if (!txn) {
		fprintf(stderr, "client %d failed to prepare transaction buffer\n", id);
		return -1;
	}

	bwr.write_buffer = (unsigned long)txn;
	bwr.read_buffer = (unsigned long)rbuf;

	inst = (inst_buf_t *)txn->tdata.data.ptr.buffer;
	INST_INIT(inst);

	ibuf = malloc((iterations + 1) * sizeof(inst_entry_t) * INSTRUCTING_MAX_ENTRIES);
	if (!ibuf)
		fprintf(stderr, "client %d failed to allocate instrumenting buffer\n", id);

	p = ibuf;
	n = iterations + 1;
	while (n-- > 0) {
		INST_START(inst);

		bwr.write_size = sizeof(*txn);
		bwr.write_consumed = 0;
		bwr.read_size = sizeof(rbuf);
		bwr.read_consumed = 0;

		retries = 2;

		INST_ENTRY(inst, "C_IO_IN");

wait_reply:
		r = ioctl(fd, BINDER_WRITE_READ, &bwr);
		if (r < 0) {
			fprintf(stderr, "client %d failed ioctl\n", id);
			return r;
		}
		INST_RECORD(&copy);

		r = client_parse_command(id, rbuf, bwr.read_consumed, &inst);
		if (r < 0)
			return r;

		if (!inst) {
			if (retries-- > 0) {
				bwr.write_size = 0;
				bwr.read_consumed = 0;
				goto wait_reply;
			} else {
				fprintf(stderr, "client %d failed to receive reply\n", id);
				return -1;
			}
		}

		INST_ENTRY_COPY(inst, "C_IO_OUT", &copy);
		INST_ENTRY(inst, "C_EXIT");

		INST_END(inst, p);
		p += sizeof(inst_entry_t) * INSTRUCTING_MAX_ENTRIES;
	}

	if (output_file) {
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
			if (n)
				fprintf(fp, "%ld.%ld, ", entry->tv.tv_sec, entry->tv.tv_usec);
			else
				fprintf(fp, "%s, ", entry->label);

			entry++;
		}
		fprintf(fp, "\n");
	}

	if (fp != stdout)
		fclose(fp);
	free(txn);

	return 0;
}

int main(int argc, char **argv)
{
	int clients, i, r, stat;
	pid_t pid;

	clients = 1;
	for (i = 0; i < clients; i++) {
		pid = fork();

		if (!pid) {
			client_main(i);
			exit(0);
		} else if (pid < 0) {
			fprintf(stderr, "server fork error\n");
			return -1;
		}
	}

	server_main();

	while (clients-- > 0) {
		r = wait(&stat);
		if (r == -1 && errno == ECHILD) {
			fprintf(stderr, "no more clients to wait\n");
			break;
		}
	}

	return 0;
}
