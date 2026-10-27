// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Abd-Alrhman Masalkhi
 *
 *    Talk to the md driver through the /dev/md-control node, and fall back
 *    to the old per-array ioctls when the node is not available.
 *
 *    Author: Abd-Alrhman Masalkhi
 *    Email: <abd.masalkhi@gmail.com>
 */

#include	"mdadm.h"

#ifndef __has_builtin
#define __has_builtin(foo) 0
#endif

#define assign_field_nocheck(dest, src, field, bad)	\
	do {						\
		(dest)->field = (src)->field;		\
	} while (0)

#if (defined __GNUC__ && __GNUC__ >= 5) || __has_builtin(__builtin_add_overflow)
#define assign_field_check(dest, src, field, bad)			\
	do {								\
		(bad) |= __builtin_add_overflow((src)->field, 0, &(dest)->field); \
	} while (0)
#else
/* TODO: Add a non buildin overflow checking for this implementation */
#define assign_field_check(dest, src, field, bad)	\
	assign_field_nocheck(dest, src, field, bad)
#endif

#define convert_array_info(dest, src, suffix)				\
	({								\
		bool bad = false;					\
		typeof(src) __s = (src);				\
		typeof(dest) __d = (dest);				\
									\
		memset(__d, 0, sizeof(*__d));				\
		assign_field_##suffix(__d, __s, major_version, bad);	\
		assign_field_##suffix(__d, __s, minor_version, bad);	\
		assign_field_##suffix(__d, __s, patch_version, bad);	\
		assign_field_##suffix(__d, __s, ctime, bad);		\
		assign_field_##suffix(__d, __s, level, bad);		\
		assign_field_##suffix(__d, __s, size, bad);		\
		assign_field_##suffix(__d, __s, nr_disks, bad);		\
		assign_field_##suffix(__d, __s, raid_disks, bad);	\
		assign_field_##suffix(__d, __s, md_minor, bad);		\
		assign_field_##suffix(__d, __s, not_persistent, bad);	\
		assign_field_##suffix(__d, __s, utime, bad);		\
		assign_field_##suffix(__d, __s, state, bad);		\
		assign_field_##suffix(__d, __s, active_disks, bad);	\
		assign_field_##suffix(__d, __s, working_disks, bad);	\
		assign_field_##suffix(__d, __s, failed_disks, bad);	\
		assign_field_##suffix(__d, __s, spare_disks, bad);	\
		assign_field_##suffix(__d, __s, layout, bad);		\
		assign_field_##suffix(__d, __s, chunk_size, bad);	\
									\
		bad;							\
	})

#define convert_disk_info(dest, src, suffix)				\
	({								\
		bool bad = false;					\
		typeof(src) __s = (src);				\
		typeof(dest) __d = (dest);				\
									\
		memset(__d, 0, sizeof(*__d));				\
		assign_field_##suffix(__d, __s, number, bad);		\
		assign_field_##suffix(__d, __s, major, bad);		\
		assign_field_##suffix(__d, __s, minor, bad);		\
		assign_field_##suffix(__d, __s, raid_disk, bad);	\
		assign_field_##suffix(__d, __s, state, bad);		\
									\
		bad;							\
	})

#define convert_param(dest, src, suffix)				\
	({								\
		bool bad = false;					\
		typeof(src) __s = (src);				\
		typeof(dest) __d = (dest);				\
									\
		memset(__d, 0, sizeof(*__d));				\
		assign_field_##suffix(__d, __s, personality, bad);	\
		assign_field_##suffix(__d, __s, chunk_size, bad);	\
		assign_field_##suffix(__d, __s, max_fault, bad);	\
									\
		bad;							\
	})

#define convert_version(dest, src, suffix)				\
	({								\
		bool bad = false;					\
		typeof(src) __s = (src);				\
		typeof(dest) __d = (dest);				\
									\
		memset(__d, 0, sizeof(*__d));				\
		assign_field_##suffix(__d, __s, major, bad);		\
		assign_field_##suffix(__d, __s, minor, bad);		\
		assign_field_##suffix(__d, __s, patchlevel, bad);	\
									\
		bad;							\
	})

/* Commands that are not directed at a particular array. */
static inline bool cmd_is_global(unsigned long cmd)
{
	return cmd == MD_CTL_RAID_VERSION;
}

static bool param_from64(mdu_param_t *param, struct mdu_param64 *param64)
{
	return convert_param(param, param64, check);
}

static bool version_to64(struct mdu_version64 *v64, mdu_version_t *v)
{
	return convert_version(v64, v, check);
}

static bool disk_info_to64(struct mdu_disk_info64 *info64, mdu_disk_info_t *info)
{
	return convert_disk_info(info64, info, check);
}

static bool disk_info_from64(mdu_disk_info_t *info,
			     struct mdu_disk_info64 *info64)
{
	return convert_disk_info(info, info64, check);
}

static bool array_info_to64(struct mdu_array_info64 *info64,
			    mdu_array_info_t *info)
{
	return convert_array_info(info64, info, check);
}

static bool array_info_from64(mdu_array_info_t *info,
			      struct mdu_array_info64 *info64)
{
	return convert_array_info(info, info64, check);
}

static int handle_old_ioctl(int fd, unsigned long cmd, __u64 arg, __u32 flags)
{
	int rv = -1;

	switch (cmd) {
	case MD_CTL_RAID_VERSION: {
		mdu_version_t v = {0};

		rv = ioctl(fd, RAID_VERSION, &v);
		if (!rv)
			if (version_to64(u64_to_ptr(arg), &v))
				rv = -1;
		return rv;
	}

	case MD_CTL_GET_ARRAY_INFO:  {
		mdu_array_info_t array;

		rv = ioctl(fd, GET_ARRAY_INFO, &array);
		if (!rv)
			if (array_info_to64(u64_to_ptr(arg), &array))
				rv = -1;
		return rv;
	}

	case MD_CTL_SET_ARRAY_INFO: {
		mdu_array_info_t array;

		if (array_info_from64(&array, u64_to_ptr(arg)))
			return -1;
		return ioctl(fd, SET_ARRAY_INFO, &array);
	}

	case MD_CTL_GET_DISK_INFO: {
		struct mdu_disk_info64 *argp = u64_to_ptr(arg);
		mdu_disk_info_t disk = {.number = argp->number};

		rv = ioctl(fd, GET_DISK_INFO, &disk);
		if (!rv)
			if (disk_info_to64(u64_to_ptr(arg), &disk))
				return -1;
		return rv;
	}

	case MD_CTL_ADD_NEW_DISK: {
		mdu_disk_info_t disk;

		if (disk_info_from64(&disk, u64_to_ptr(arg)))
			return -1;
		return ioctl(fd, ADD_NEW_DISK, &disk);
	}

	case MD_CTL_RUN_ARRAY: {
		mdu_param_t param;

		if (arg && param_from64(&param, u64_to_ptr(arg)))
			return -1;
		return ioctl(fd, RUN_ARRAY, arg ? &param : NULL);
	}

	case MD_CTL_GET_BITMAP_FILE:
		return ioctl(fd, GET_BITMAP_FILE, u64_to_ptr(arg));

	case MD_CTL_SET_BITMAP_FILE:
		return ioctl(fd, SET_BITMAP_FILE, (long)arg);

	case MD_CTL_HOT_REMOVE_DISK:
		return ioctl(fd, HOT_REMOVE_DISK, (long)arg);

	case MD_CTL_SET_DISK_FAULTY:
		return ioctl(fd, SET_DISK_FAULTY, (long)arg);

	case MD_CTL_STOP_ARRAY:
		if (flags & MD_CTL_RO_FLAG)
			return ioctl(fd, STOP_ARRAY_RO, 0);
		else
			return ioctl(fd, STOP_ARRAY, 0);

	case MD_CTL_RESTART_ARRAY_RW:
		return ioctl(fd, RESTART_ARRAY_RW, 0);

	case MD_CTL_CLUSTERED_DISK_NACK:
		return ioctl(fd, CLUSTERED_DISK_NACK, 0);
	}

	return -1;
}

static int mdctl_init(struct mdu_ioctl *ctl, char *uuid, dev_t dev, char *devnm,
		      __u64 arg, __u32 flags)
{
	memset(ctl, 0, sizeof(*ctl));
	if (uuid)
		memcpy(ctl->md_uuid, uuid, MD_UUID_LEN);
	else if (dev)
		ctl->md_dev = dev;
	else if (devnm)
		snprintf(ctl->md_name, MD_NAME_LEN, "%s", devnm);
	else
		return -1;
	ctl->arg = arg;
	ctl->flags = flags;
	return 0;
}

int md_do_ioctl(int fd, char *uuid, dev_t dev, char *devnm, unsigned long cmd,
		__u64 arg, __u32 flags)
{
	int rv = -1;
	struct mdu_ioctl mdctl;
	int ctl_node_fd = open_mdctl();

	if (ctl_node_fd < 0)
		rv = handle_old_ioctl(fd, cmd, arg, flags);
	else if (cmd_is_global(cmd))
		rv = ioctl(ctl_node_fd, cmd, u64_to_ptr(arg));
	else if (!mdctl_init(&mdctl, uuid, dev, devnm, arg, flags))
		rv = ioctl(ctl_node_fd, cmd, &mdctl);
	else
		assert(fd < 0);

	return rv;
}

static int ctlfd = -2;

/**
 * Opens the md control node. For multiple successive calls, only the first
 * call will attempt to open the control node, while subsequent calls will
 * simply return the value stored in ctlfd.
 *
 * On success, return filedescriptor.
 * On failure, return -1.
 */
int open_mdctl(void)
{
	if (ctlfd != -2)
		return ctlfd;

	if (!getenv("MDADM_NO_CTL_NODE"))
		ctlfd = open("/dev/" MD_CTL_NODE, O_RDWR);
	else
		ctlfd = -1;

	return ctlfd;
}

void close_mdctl(void)
{
	close_fd(&ctlfd);
}

bool is_mdctl_available(void)
{
	return open_mdctl() != -1;
}
