/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef MDDEV_H
#define MDDEV_H

/* Values for create_mddev()'s trustworthy argument. */
#define LOCAL 1
#define LOCAL_ANY 10
#define FOREIGN 2
#define METADATA 3

int create_mddev(char *dev, char *name, int trustworthy, char *chosen, int block_udev);
int open_mddev(char *dev, int report_errors);
int is_mddev(char *dev);

#endif
