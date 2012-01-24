#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#ifndef uint8_t 
#define uint8_t unsigned char
#endif

#include "binder.h"

#define ALIGN(n)	(((n) + 3) & ~3)


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
		printf("\n");
}

void objdump(const void *data, const void *offsets, unsigned long offsets_size)
{
	size_t *p = (size_t *)offsets, *ep = (size_t *)((unsigned char *)offsets + offsets_size);
	struct flat_binder_object *obj;
	int n = 0;

	while (p < ep) {
		obj = (struct flat_binder_object *)((unsigned char *)data + *p++);

		printf("\tObj #%d\n", ++n);
		printf("\t\ttype: %lu\n", obj->type);
		printf("\t\tflags: %lu\n", obj->flags);
		printf("\t\tbinder: %p\n", obj->binder);
		printf("\t\tcookie: %p\n", obj->cookie);
	}
}

int parse_command(int fd, void *buf, unsigned long size)
{
	unsigned char *p, *ep;
	unsigned int cmd;
	struct binder_transaction_data *tdata;
	unsigned long buffer_size;

	p = buf;
	ep = p + size;
	while (p < ep) {
		cmd = *(unsigned int *)p;
		p += sizeof(cmd);

		switch (cmd) {
			case BR_NOOP:
				printf("rcv NOOP\n");
				break;

			case BR_TRANSACTION_COMPLETE:
				printf("rcv TRANSCATION_COMPLETE\n");
				break;

			case BR_INCREFS:
			case BR_ACQUIRE:
			case BR_RELEASE:
			case BR_DECREFS:
				printf("rcv REF_CMD: %u\n", cmd);
				if (p + 2 * sizeof(cmd) > ep) {
					fprintf(stderr, "not enough ref_cmd data\n");
					return -1;
				}
				p += 2 * sizeof(cmd);
				break;

			case BR_TRANSACTION:
				printf("rcv TRANSACTION\n");
				if (p + sizeof(*tdata) > ep) {
					fprintf(stderr, "not enough transaction data\n");
					return -1;
				}

				tdata = (struct binder_transaction_data *)p;
				printf("\thandle: %ld\n", (unsigned long)tdata->target.handle);
				printf("\tcookie: %p\n", tdata->cookie);
				printf("\tcode: %u\n", tdata->code);
				printf("\tflags: %u\n", tdata->flags);
				printf("\tpid: %u\n", tdata->sender_pid);
				printf("\tuid: %u\n", tdata->sender_euid);
				printf("\tdata_size: %u\n", tdata->data_size);
				printf("\toffsets_size: %u\n", tdata->offsets_size);
				printf("\tbuffer: %p\n", tdata->data.ptr.buffer);
				printf("\toffsets: %p\n", tdata->data.ptr.offsets);

				p += sizeof(*tdata);
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "not enough transaction data buffer\n");
					return -1;
				}

				printf("Data dump:\n");
				hexdump(tdata->data.ptr.buffer, tdata->data_size);

				printf("Offsets dump:\n");
				hexdump(tdata->data.ptr.offsets, tdata->offsets_size);

				printf("Objects dump:\n");
				objdump(tdata->data.ptr.buffer, tdata->data.ptr.offsets, tdata->offsets_size);

				p += buffer_size;
				break;

			case BR_REPLY:
				printf("rcv REPLY\n");
				if (p + sizeof(*tdata) > ep) {
					fprintf(stderr, "not enough reply data\n");
					return -1;
				}

				tdata = (struct binder_transaction_data *)p;
				printf("\thandle: %ld\n", (unsigned long)tdata->target.handle);
				printf("\tcookie: %p\n", tdata->cookie);
				printf("\tcode: %u\n", tdata->code);
				printf("\tflags: %u\n", tdata->flags);
				printf("\tpid: %u\n", tdata->sender_pid);
				printf("\tuid: %u\n", tdata->sender_euid);
				printf("\tdata_size: %u\n", tdata->data_size);
				printf("\toffsets_size: %u\n", tdata->offsets_size);
				printf("\tbuffer: %p\n", tdata->data.ptr.buffer);
				printf("\toffsets: %p\n", tdata->data.ptr.offsets);

				p += sizeof(*tdata);
				buffer_size = ALIGN(tdata->data_size) + ALIGN(tdata->offsets_size);
				if (p + buffer_size > ep) {
					fprintf(stderr, "not enough reply data buffer\n");
					return -1;
				}

				printf("Data dump:\n");
				hexdump(tdata->data.ptr.buffer, tdata->data_size);

				printf("Offsets dump:\n");
				hexdump(tdata->data.ptr.offsets, tdata->offsets_size);

				printf("Objects dump:\n");
				objdump(tdata->data.ptr.buffer, tdata->data.ptr.offsets, tdata->offsets_size);

				p += buffer_size;
				break;

			case BR_DEAD_BINDER:
				printf("rcv DEAD_BINDER\n");
				if (p + sizeof(cmd) > ep) {
					fprintf(stderr, "not enough dead binder data\n");
					return -1;
				}

				p += sizeof(cmd);
				break;

			case BR_FAILED_REPLY:
				printf("rcv FAILED_BINDER\n");
				break;

			case BR_DEAD_REPLY:
				printf("rcv DEAD_BINDER\n");
				break;

			default:
				fprintf(stderr, "rcv unknown command: %u\n", cmd);
				return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int fd, r;
	struct binder_write_read bwr;
	unsigned int wbuf[1024], rbuf[1024];
	struct binder_transaction_data *tdata;
	struct flat_binder_object *obj;
	size_t *offsets;

	fd = open("/dev/binder", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Failed to open binder device\n");
		return -1;
	}

	wbuf[0] = BC_TRANSACTION;
	tdata = (struct binder_transaction_data *)(&wbuf[1]);
	obj = (struct flat_binder_object *)((unsigned char *)tdata + ALIGN(sizeof(*tdata)));
	offsets = (size_t *)((unsigned char *)obj + ALIGN(sizeof(*obj)));

	memset(tdata, 0, sizeof(*tdata));
	memset(obj, 0, sizeof(*obj));

	tdata->target.handle = 0;
	tdata->cookie = (void *)0xc00c1e;
	tdata->code = 1;
	tdata->data_size = sizeof(*obj);
	tdata->offsets_size = sizeof(size_t);
	tdata->data.ptr.buffer = obj;
	tdata->data.ptr.offsets = offsets;

	obj->type = BINDER_TYPE_BINDER;
	obj->flags = 0;
	obj->binder = (void *)0x1234;
	obj->cookie = (void *)0x5678;
	
	offsets[0] = 0;

	memset(&bwr, 0, sizeof(bwr));
	bwr.write_buffer = (unsigned long)wbuf;
	bwr.write_size = sizeof(wbuf[0]) + sizeof(*tdata);

	r = ioctl(fd, BINDER_WRITE_READ, &bwr);
	if (r < 0) {
		fprintf(stderr, "Failed to write command: %d\n", errno);
		return -1;
	}

	while (1) {
		memset(&bwr, 0, sizeof(bwr));
		bwr.read_buffer = (unsigned long)rbuf;
		bwr.read_size = sizeof(rbuf);

		r = ioctl(fd, BINDER_WRITE_READ, &bwr);
		if (r < 0) {
			fprintf(stderr, "Failed to write command: %d\n", errno);
			return -1;
		}

		if (bwr.read_consumed > 0) {
			r = parse_command(fd, rbuf, bwr.read_consumed);
			if (r < 0) 
				return -1;
		}
	}

	return 0;
}
