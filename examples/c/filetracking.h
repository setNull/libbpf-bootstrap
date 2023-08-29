/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __FILETRACKING_H
#define __FILETRACKING_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128

struct event {
	int inode_index;
	int data_index;
	int block_count;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

#endif /* __FILETRACKING_H */
