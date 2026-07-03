/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef MDSTAT_H
#define MDSTAT_H

#include <signal.h>
#include <stdbool.h>
#include <string.h>

struct mdstat_ent {
	char devnm[32];

	char *metadata_version;
	int raid_disks;
	char *pattern;		/* U for up, _ for down */
	char *level;
	int percent;		/* -1 if no resync */
	int active;
	int resync;		/* 3 if check, 2 if reshape, 1 if resync, 0 if recovery */
	int devcnt;

	struct dev_member {
		char *name;
		struct dev_member *next;
	} *members;
	struct mdstat_ent *next;
};

struct mdstat_ent *mdstat_find_by_member_name(struct mdstat_ent *mdstat, char *member_devnm);
struct mdstat_ent *mdstat_by_subdev(char *subdev, char *container);
struct mdstat_ent *mdstat_by_component(char *name);
struct mdstat_ent *mdstat_read(int hold, int start);

void free_mdstat(struct mdstat_ent *ms);
void mdstat_close(void);

void mdstat_wait_fd(int fd, const sigset_t *sigmask);
int mdstat_wait(int seconds);
int mddev_busy(char *devnm);

bool is_mdstat_ent_external(struct mdstat_ent *ent);
bool is_mdstat_ent_subarray(struct mdstat_ent *ent);
bool is_container_member(struct mdstat_ent *ent, char *devname);

int is_subarray_active(char *subarray, char *container);

static inline char *to_subarray(struct mdstat_ent *ent, char *container)
{
	return &ent->metadata_version[10+strlen(container)+1];
}

#endif
