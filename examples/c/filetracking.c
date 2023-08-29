// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include "filetracking.skel.h"
#include "filetracking.h"

int verbose = 0;
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event * e = data;
	if (e->inode_index) {
		printf("Filename <%s> is deleted by <%s>\n",
			e->filename, e->comm);
	}
	else {
		printf("Filename <%s> is moditied by <%s>, LBA is 0x%x\n",
			e->filename, e->comm, e->data_index * 8);
	}
	return 0;
}

#define MAX_LINE_LENGTH (MAX_FILENAME_LEN + 20)

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct filetracking_bpf *skel;
	int err;
    FILE *file;
    char line[MAX_LINE_LENGTH];
	char filename[MAX_FILENAME_LEN];
	int inode_index = 0;
	int data_index = 0;
	int data_count = 0;
	int ino_fd,data_fd;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);


	skel = filetracking_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = filetracking_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = filetracking_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    file = fopen("/tmp/filetracking.conf", "r");
    if (file == NULL) {
        printf("open file failed\n");
        return -1;
    }

    while (fgets(line, MAX_LINE_LENGTH, file) != NULL) {
		if (strcmp(line, "\n") == 0) {
            break;
        }
        // TODO: generate inode_map, data_map
		sscanf(line, "%[^:]:%d,%d,%d", filename, &inode_index, &data_index, &data_count);
		printf("parsed <%s>:%d,%d,%d\n", filename, inode_index, data_index, data_count);
		ino_fd = bpf_map__fd(skel->maps.inode_map);
		data_fd = bpf_map__fd(skel->maps.data_map);
		if (bpf_map_update_elem(ino_fd, &inode_index, filename, BPF_ANY)) {
			fprintf(stderr, "Failed adding inode to map");
			goto cleanup;
		}
		for (int num = 0; num < data_count; num++) {
			int tmp = data_index + num;
			if (bpf_map_update_elem(data_fd, &tmp, filename, BPF_ANY)) {
				fprintf(stderr, "Failed adding data to map");
				goto cleanup;
			}
		}
	}
    fclose(file);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Successfully started!\n");

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	if (ino_fd > 0)
		close(ino_fd);
	if (data_fd > 0)
		close(data_fd);
	ring_buffer__free(rb);
	filetracking_bpf__destroy(skel);
	return -err;
}
