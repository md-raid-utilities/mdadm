/*
 * mdadm - manage Linux "md" devices aka RAID arrays.
 *
 * Copyright (C) 2001-2013 Neil Brown <neilb@suse.de>
 *
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *    Author: Neil Brown
 *    Email: <neilb@suse.de>
 */

#include	"mdadm.h"
#include	"md_p.h"
#include	"xmalloc.h"

#include	<sys/socket.h>
#include	<sys/utsname.h>
#include	<sys/wait.h>
#include	<sys/un.h>
#include	<sys/resource.h>
#include	<sys/vfs.h>
#include	<sys/mman.h>
#include	<linux/magic.h>
#include	<poll.h>
#include	<ctype.h>
#include	<dirent.h>
#include	<dlfcn.h>
#include	<limits.h>

/*
 * following taken from linux/blkpg.h because they aren't
 * anywhere else and it isn't safe to #include linux/ * stuff.
 */

#define BLKPG      _IO(0x12,105)

/* The argument structure */
struct blkpg_ioctl_arg {
	int op;
	int flags;
	int datalen;
	void *data;
};

/* The subfunctions (for the op field) */
#define BLKPG_ADD_PARTITION	1
#define BLKPG_DEL_PARTITION	2

/* Sizes of name fields. Unused at present. */
#define BLKPG_DEVNAMELTH	64
#define BLKPG_VOLNAMELTH	64

/* The data structure for ADD_PARTITION and DEL_PARTITION */
struct blkpg_partition {
	long long start;		/* starting offset in bytes */
	long long length;		/* length in bytes */
	int pno;			/* partition number */
	char devname[BLKPG_DEVNAMELTH];	/* partition name, like sda5 or c0d1p2,
					   to be used in kernel messages */
	char volname[BLKPG_VOLNAMELTH];	/* volume label */
};

#include "part.h"

/* Force a compilation error if condition is true */
#define BUILD_BUG_ON(condition) ((void)BUILD_BUG_ON_ZERO(condition))

/* Force a compilation error if condition is true, but also produce a
   result (of value 0 and type size_t), so the expression can be used
   e.g. in a structure initializer (or where-ever else comma expressions
   aren't permitted). */
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))

static int is_dlm_hooks_ready = 0;

int dlm_funs_ready(void)
{
	return is_dlm_hooks_ready ? 1 : 0;
}

static struct dlm_hooks *dlm_hooks = NULL;
struct dlm_lock_resource *dlm_lock_res = NULL;
static int ast_called = 0;

struct dlm_lock_resource {
	dlm_lshandle_t *ls;
	struct dlm_lksb lksb;
};

/* Using poll(2) to wait for and dispatch ASTs */
static int poll_for_ast(dlm_lshandle_t ls)
{
	struct pollfd pfd;

	pfd.fd = dlm_hooks->ls_get_fd(ls);
	pfd.events = POLLIN;

	while (!ast_called)
	{
		if (poll(&pfd, 1, 0) < 0)
		{
			perror("poll");
			return -1;
		}
		dlm_hooks->dispatch(dlm_hooks->ls_get_fd(ls));
	}
	ast_called = 0;

	return 0;
}

static void dlm_ast(void *arg)
{
	ast_called = 1;
}

static char *cluster_name = NULL;
/* Create the lockspace, take bitmapXXX locks on all the bitmaps. */
int cluster_get_dlmlock(void)
{
	int ret = -1;
	char str[64];
	int flags = LKF_NOQUEUE;
	int retry_count = 0;

	if (!dlm_funs_ready()) {
		pr_err("Something wrong with dlm library\n");
		return -1;
	}

	ret = get_cluster_name(&cluster_name);
	if (ret) {
		pr_err("The md can't get cluster name\n");
		return -1;
	}

	dlm_lock_res = xmalloc(sizeof(struct dlm_lock_resource));
	dlm_lock_res->ls = dlm_hooks->open_lockspace(cluster_name);
	if (!dlm_lock_res->ls) {
		dlm_lock_res->ls = dlm_hooks->create_lockspace(cluster_name, O_RDWR);
		if (!dlm_lock_res->ls) {
			pr_err("%s failed to create lockspace\n", cluster_name);
			return -ENOMEM;
		}
	} else {
		pr_err("open existed %s lockspace\n", cluster_name);
	}

	snprintf(str, 64, "bitmap%s", cluster_name);
retry:
	ret = dlm_hooks->ls_lock(dlm_lock_res->ls, LKM_PWMODE,
				 &dlm_lock_res->lksb, flags, str, strlen(str),
				 0, dlm_ast, dlm_lock_res, NULL, NULL);
	if (ret) {
		pr_err("error %d when get PW mode on lock %s\n", errno, str);
		/* let's try several times if EAGAIN happened */
		if (dlm_lock_res->lksb.sb_status == EAGAIN && retry_count < 10) {
			sleep_for(10, 0, true);
			retry_count++;
			goto retry;
		}
		dlm_hooks->release_lockspace(cluster_name, dlm_lock_res->ls, 1);
		return ret;
	}

	/* Wait for it to complete */
	poll_for_ast(dlm_lock_res->ls);

	if (dlm_lock_res->lksb.sb_status) {
		pr_err("failed to lock cluster\n");
		return -1;
	}
	return 1;
}

int cluster_release_dlmlock(void)
{
	int ret = -1;

	if (!cluster_name)
                goto out;

	if (!dlm_lock_res->lksb.sb_lkid)
                goto out;

	ret = dlm_hooks->ls_unlock_wait(dlm_lock_res->ls,
					dlm_lock_res->lksb.sb_lkid, 0,
					&dlm_lock_res->lksb);
	if (ret) {
		pr_err("error %d happened when unlock\n", errno);
		/* XXX make sure the lock is unlocked eventually */
                goto out;
	}

	/* Wait for it to complete */
	poll_for_ast(dlm_lock_res->ls);

	errno =	dlm_lock_res->lksb.sb_status;
	if (errno != EUNLOCK) {
		pr_err("error %d happened in ast when unlock lockspace\n",
		       errno);
		/* XXX make sure the lockspace is unlocked eventually */
                goto out;
	}

	ret = dlm_hooks->release_lockspace(cluster_name, dlm_lock_res->ls, 1);
	if (ret) {
		pr_err("error %d happened when release lockspace\n", errno);
		/* XXX make sure the lockspace is released eventually */
                goto out;
	}
	free(dlm_lock_res);

out:
	return ret;
}

int md_array_valid(int fd)
{
	struct mdinfo *sra;
	int ret;

	sra = sysfs_read(fd, NULL, GET_ARRAY_STATE);
	if (sra) {
		if (sra->array_state != ARRAY_UNKNOWN_STATE)
			ret = 0;
		else
			ret = -ENODEV;

		free(sra);
	} else {
		/*
		 * GET_ARRAY_INFO doesn't provide access to the proper state
		 * information, so fallback to a basic check for raid_disks != 0
		 */
		ret = ioctl(fd, RAID_VERSION);
	}

	return !ret;
}

int md_array_active(int fd)
{
	struct mdinfo *sra;
	struct mdu_array_info_s array;
	int ret = 0;

	sra = sysfs_read(fd, NULL, GET_ARRAY_STATE);
	if (sra) {
		if (!md_array_is_active(sra))
			ret = -ENODEV;

		free(sra);
	} else {
		/*
		 * GET_ARRAY_INFO doesn't provide access to the proper state
		 * information, so fallback to a basic check for raid_disks != 0
		 */
		ret = md_get_array_info(fd, &array);
	}

	return !ret;
}

int md_array_is_active(struct mdinfo *info)
{
	return (info->array_state != ARRAY_CLEAR &&
		info->array_state != ARRAY_INACTIVE &&
		info->array_state != ARRAY_UNKNOWN_STATE);
}

/*
 * Get array info from the kernel. Longer term we want to deprecate the
 * ioctl and get it from sysfs.
 */
int md_get_array_info(int fd, struct mdu_array_info_s *array)
{
	return ioctl(fd, GET_ARRAY_INFO, array);
}

/*
 * Set array info
 */
int md_set_array_info(int fd, struct mdu_array_info_s *array)
{
	return ioctl(fd, SET_ARRAY_INFO, array);
}

/*
 * Get disk info from the kernel.
 */
int md_get_disk_info(int fd, struct mdu_disk_info_s *disk)
{
	return ioctl(fd, GET_DISK_INFO, disk);
}

int get_linux_version()
{
	struct utsname name;
	char *cp;
	int a = 0, b = 0,c = 0;
	if (uname(&name) <0)
		return -1;

	cp = name.release;
	a = strtoul(cp, &cp, 10);
	if (*cp == '.')
		b = strtoul(cp+1, &cp, 10);
	if (*cp == '.')
		c = strtoul(cp+1, &cp, 10);

	return (a*1000000)+(b*1000)+c;
}

int mdadm_version(char *version)
{
	int a, b, c;
	char *cp;

	if (!version)
		version = Version;

	cp = strchr(version, '-');
	if (!cp || *(cp+1) != ' ' || *(cp+2) != 'v')
		return -1;
	cp += 3;
	a = strtoul(cp, &cp, 10);
	if (*cp != '.')
		return -1;
	b = strtoul(cp+1, &cp, 10);
	if (*cp == '.')
		c = strtoul(cp+1, &cp, 10);
	else
		c = 0;
	if (*cp != ' ' && *cp != '-')
		return -1;
	return (a*1000000)+(b*1000)+c;
}

unsigned long long parse_size(char *size)
{
	/* parse 'size' which should be a number optionally
	 * followed by 'K', 'M'. 'G' or 'T'.
	 * Without a suffix, K is assumed.
	 * Number returned is in sectors (half-K)
	 * INVALID_SECTORS returned on error.
	 */
	char *c;
	long long s = strtoll(size, &c, 10);
	if (s > 0) {
		switch (*c) {
		case 'K':
			c++;
		default:
			s *= 2;
			break;
		case 'M':
			c++;
			s *= 1024 * 2;
			break;
		case 'G':
			c++;
			s *= 1024 * 1024 * 2;
			break;
		case 'T':
			c++;
			s *= 1024 * 1024 * 1024 * 2LL;
			break;
		case 's': /* sectors */
			c++;
			break;
		}
	} else
		s = INVALID_SECTORS;
	if (*c)
		s = INVALID_SECTORS;
	return s;
}

int is_near_layout_10(int layout)
{
	int fc, fo;

	fc = (layout >> 8) & 255;
	fo = layout & (1 << 16);
	if (fc > 1 || fo > 0)
		return 0;
	return 1;
}

int parse_layout_10(char *layout)
{
	int copies, rv;
	char *cp;
	/* Parse the layout string for raid10 */
	/* 'f', 'o' or 'n' followed by a number <= raid_disks */
	if ((layout[0] !=  'n' && layout[0] != 'f' && layout[0] != 'o') ||
	    (copies = strtoul(layout+1, &cp, 10)) < 1 ||
	    copies > 200 ||
	    *cp)
		return -1;
	if (layout[0] == 'n')
		rv = 256 + copies;
	else if (layout[0] == 'o')
		rv = 0x10000 + (copies<<8) + 1;
	else
		rv = 1 + (copies<<8);
	return rv;
}

int parse_layout_faulty(char *layout)
{
	int ln, mode;
	char *m;

	if (!layout)
		return -1;

	/* Parse the layout string for 'faulty' */
	ln = strcspn(layout, "0123456789");
	m = xstrdup(layout);
	m[ln] = 0;
	mode = map_name(faultylayout, m);
	free(m);

	if (mode == UnSet)
		return -1;

	return mode | (atoi(layout+ln)<< ModeShift);
}

int parse_cluster_confirm_arg(char *input, char **devname, int *slot)
{
	char *dev;
	*slot = strtoul(input, &dev, 10);
	if (dev == input || dev[0] != ':')
		return -1;
	*devname = dev+1;
	return 0;
}

void remove_partitions(int fd)
{
	/* remove partitions from this block devices.
	 * This is used for components added to an array
	 */
#ifdef BLKPG_DEL_PARTITION
	struct blkpg_ioctl_arg a;
	struct blkpg_partition p;

	a.op = BLKPG_DEL_PARTITION;
	a.data = (void*)&p;
	a.datalen = sizeof(p);
	a.flags = 0;
	memset(a.data, 0, a.datalen);
	for (p.pno = 0; p.pno < 16; p.pno++)
		ioctl(fd, BLKPG, &a);
#endif
}

int test_partition(int fd)
{
	/* Check if fd is a whole-disk or a partition.
	 * BLKPG will return EINVAL on a partition, and BLKPG_DEL_PARTITION
	 * will return ENXIO on an invalid partition number.
	 */
	struct blkpg_ioctl_arg a;
	struct blkpg_partition p;
	a.op = BLKPG_DEL_PARTITION;
	a.data = (void*)&p;
	a.datalen = sizeof(p);
	a.flags = 0;
	memset(a.data, 0, a.datalen);
	p.pno = 1<<30;
	if (ioctl(fd, BLKPG, &a) == 0)
		/* Very unlikely, but not a partition */
		return 0;
	if (errno == ENXIO || errno == ENOTTY)
		/* not a partition */
		return 0;

	return 1;
}

int test_partition_from_id(dev_t id)
{
	char buf[20];
	int fd, rv;

	sprintf(buf, "%d:%d", major(id), minor(id));
	fd = dev_open(buf, O_RDONLY);
	if (fd < 0)
		return -1;
	rv = test_partition(fd);
	close(fd);
	return rv;
}

int enough(int level, int raid_disks, int layout, int clean, char *avail)
{
	int copies, first;
	int i;
	int avail_disks = 0;

	if (raid_disks <= 0)
		return 0;

	for (i = 0; i < raid_disks; i++)
		avail_disks += !!avail[i];

	switch (level) {
	case 10:
		/* This is the tricky one - we need to check
		 * which actual disks are present.
		 */
		copies = (layout & 255) * ((layout >> 8) & 255);
		first = 0;
		do {
			/* there must be one of the 'copies' form 'first' */
			int n = copies;
			int cnt = 0;
			int this = first;
			while (n--) {
				if (avail[this])
					cnt++;
				this = (this + 1) % raid_disks;
			}
			if (cnt == 0)
				return 0;
			first = (first + (layout & 255)) % raid_disks;
		} while (first != 0);
		return 1;

	case LEVEL_MULTIPATH:
		return avail_disks >= 1;
	case LEVEL_LINEAR:
	case 0:
		return avail_disks == raid_disks;
	case 1:
		return avail_disks >= 1;
	case 4:
		if (avail_disks == raid_disks - 1 &&
		    !avail[raid_disks - 1])
			/* If just the parity device is missing, then we
			 * have enough, even if not clean
			 */
			return 1;
		/* FALL THROUGH */
	case 5:
		if (clean)
			return avail_disks >= raid_disks - 1;
		else
			return avail_disks >= raid_disks;
	case 6:
		if (clean)
			return avail_disks >= raid_disks - 2;
		else
			return avail_disks >= raid_disks;
	default:
		return 0;
	}
}

char *__fname_from_uuid(int id[4], int swap, char *buf, char sep)
{
	int i, j;
	char uuid[16];
	char *c = buf;
	strcpy(c, "UUID-");
	c += strlen(c);
	copy_uuid(uuid, id, swap);
	for (i = 0; i < 4; i++) {
		if (i)
			*c++ = sep;
		for (j = 3; j >= 0; j--) {
			sprintf(c,"%02x", (unsigned char) uuid[j+4*i]);
			c+= 2;
		}
	}
	return buf;

}

/**
 * fname_from_uuid() - generate uuid string. Should not be used with super1.
 * @info: info with uuid
 * @buf: buf to fill.
 *
 * This routine should not be used with super1. See detail_fname_from_uuid() for details. It does
 * not use superswitch swapuuid as it should be 0 but it has to do UUID conversion if host is big
 * endian- left for backward compatibility.
 */
char *fname_from_uuid(struct mdinfo *info, char *buf)
{
#if __BYTE_ORDER == BIG_ENDIAN
	return __fname_from_uuid(info->uuid, true, buf, ':');
#else
	return __fname_from_uuid(info->uuid, false, buf, ':');
#endif
}

int check_ext2(int fd, char *name)
{
	/*
	 * Check for an ext2fs file system.
	 * Superblock is always 1K at 1K offset
	 *
	 * s_magic is le16 at 56 == 0xEF53
	 * report mtime - le32 at 44
	 * blocks - le32 at 4
	 * logblksize - le32 at 24
	 */
	unsigned char sb[1024];
	time_t mtime;
	unsigned long long size;
	int bsize;
	if (lseek(fd, 1024,0)!= 1024)
		return 0;
	if (read(fd, sb, 1024)!= 1024)
		return 0;
	if (sb[56] != 0x53 || sb[57] != 0xef)
		return 0;

	mtime = sb[44]|(sb[45]|(sb[46]|sb[47]<<8)<<8)<<8;
	bsize = sb[24]|(sb[25]|(sb[26]|sb[27]<<8)<<8)<<8;
	size = sb[4]|(sb[5]|(sb[6]|sb[7]<<8)<<8)<<8;
	size <<= bsize;
	pr_info("%s appears to contain an ext2fs file system\n",
		name);
	pr_info("size=%lluK  mtime=%s", size, ctime(&mtime));
	return 1;
}

int check_reiser(int fd, char *name)
{
	/*
	 * superblock is at 64K
	 * size is 1024;
	 * Magic string "ReIsErFs" or "ReIsEr2Fs" at 52
	 *
	 */
	unsigned char sb[1024];
	unsigned long long size;
	if (lseek(fd, 64*1024, 0) != 64*1024)
		return 0;
	if (read(fd, sb, 1024) != 1024)
		return 0;
	if (strncmp((char*)sb+52, "ReIsErFs",8) != 0 &&
	    strncmp((char*)sb+52, "ReIsEr2Fs",9) != 0)
		return 0;
	pr_err("%s appears to contain a reiserfs file system\n",name);
	size = sb[0]|(sb[1]|(sb[2]|sb[3]<<8)<<8)<<8;
	cont_err("size = %lluK\n", size*4);

	return 1;
}

int check_raid(int fd, char *name)
{
	struct mdinfo info;
	time_t crtime;
	char *level;
	struct supertype *st = guess_super(fd);

	if (!st)
		return 0;
	if (st->ss->add_to_super != NULL) {
		st->ss->load_super(st, fd, name);
		/* Looks like a raid array .. */
		pr_err("%s appears to be part of a raid array:\n", name);
		st->ss->getinfo_super(st, &info, NULL);
		st->ss->free_super(st);
		crtime = info.array.ctime;
		level = map_num(pers, info.array.level);
		if (!level)
			level = "-unknown-";
		cont_err("level=%s devices=%d ctime=%s",
			level, info.array.raid_disks, ctime(&crtime));
	} else {
		/* Looks like GPT or MBR */
		pr_err("partition table exists on %s\n", name);
	}
	return 1;
}

int fstat_is_blkdev(int fd, char *devname, dev_t *rdev)
{
	struct stat stb;

	if (fstat(fd, &stb) != 0) {
		pr_err("fstat failed for %s: %s\n", devname, strerror(errno));
		return 0;
	}
	if ((S_IFMT & stb.st_mode) != S_IFBLK) {
		pr_err("%s is not a block device.\n", devname);
		return 0;
	}
	if (rdev)
		*rdev = stb.st_rdev;
	return 1;
}

int stat_is_blkdev(char *devname, dev_t *rdev)
{
	struct stat stb;

	if (stat(devname, &stb) != 0) {
		pr_err("stat failed for %s: %s\n", devname, strerror(errno));
		return 0;
	}
	if ((S_IFMT & stb.st_mode) != S_IFBLK) {
		pr_err("%s is not a block device.\n", devname);
		return 0;
	}
	if (rdev)
		*rdev = stb.st_rdev;
	return 1;
}

/**
 * ask() - prompt user for "yes/no" dialog.
 * @mesg: message to be printed, without '?' sign.
 * Returns: 1 if 'Y/y', 0 otherwise.
 *
 * The default value is 'N/n', thus the caps on "N" on prompt.
 */
int ask(char *mesg)
{
	char buf[3] = {0};

	fprintf(stderr, "%s [y/N]? ", mesg);
	fflush(stderr);
	if (fgets(buf, 3, stdin) == NULL)
		return 0;
	if (strlen(buf) == 1) {
		pr_err("assuming no.\n");
		return 0;
	}
	if (buf[1] != '\n')
		goto bad_option;
	if (toupper(buf[0]) == 'Y')
		return 1;
	if (toupper(buf[0]) == 'N')
		return 0;
bad_option:
	pr_err("bad option.\n");
	return 0;
}

unsigned long calc_csum(void *super, int bytes)
{
	unsigned long long newcsum = 0;
	int i;
	unsigned int csum;
	unsigned int *superc = (unsigned int*) super;

	for(i = 0; i < bytes/4; i++)
		newcsum += superc[i];
	csum = (newcsum& 0xffffffff) + (newcsum>>32);
#ifdef __alpha__
/* The in-kernel checksum calculation is always 16bit on
 * the alpha, though it is 32 bit on i386...
 * I wonder what it is elsewhere... (it uses an API in
 * a way that it shouldn't).
 */
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
#endif
	return csum;
}

char *human_size(long long bytes)
{
	static char buf[47];

	/* We convert bytes to either centi-M{ega,ibi}bytes,
	 * centi-G{igi,ibi}bytes or centi-T{era,ebi}bytes
	 * with appropriate rounding, and then print
	 * 1/100th of those as a decimal.
	 * We allow upto 2048Megabytes before converting to
	 * gigabytes and 2048Gigabytes before converting to
	 * terabytes, as that shows more precision and isn't
	 * too large a number.
	 */

	if (bytes < 5000*1024)
		buf[0] = 0;
	else if (bytes < 2*1024LL*1024LL*1024LL) {
		long cMiB = (bytes * 200LL / (1LL<<20) + 1) / 2;
		long cMB  = (bytes / ( 1000000LL / 200LL ) +1) /2;
		snprintf(buf, sizeof(buf), " (%ld.%02ld MiB %ld.%02ld MB)",
			cMiB/100, cMiB % 100, cMB/100, cMB % 100);
	} else if (bytes < 2*1024LL*1024LL*1024LL*1024LL) {
		long cGiB = (bytes * 200LL / (1LL<<30) +1) / 2;
		long cGB  = (bytes / (1000000000LL/200LL ) +1) /2;
		snprintf(buf, sizeof(buf), " (%ld.%02ld GiB %ld.%02ld GB)",
			cGiB/100, cGiB % 100, cGB/100, cGB % 100);
	} else {
		long cTiB = (bytes * 200LL / (1LL<<40) + 1) / 2;
		long cTB  = (bytes / (1000000000000LL / 200LL) + 1) / 2;
		snprintf(buf, sizeof(buf), " (%ld.%02ld TiB %ld.%02ld TB)",
			cTiB/100, cTiB % 100, cTB/100, cTB % 100);
	}
	return buf;
}

char *human_size_brief(long long bytes, int prefix)
{
	static char buf[30];

	/* We convert bytes to either centi-M{ega,ibi}bytes,
	 * centi-G{igi,ibi}bytes or centi-T{era,ebi}bytes
	 * with appropriate rounding, and then print
	 * 1/100th of those as a decimal.
	 * We allow upto 2048Megabytes before converting to
	 * gigabytes and 2048Gigabytes before converting to
	 * terabytes, as that shows more precision and isn't
	 * too large a number.
	 *
	 * If prefix == IEC, we mean prefixes like kibi,mebi,gibi etc.
	 * If prefix == JEDEC, we mean prefixes like kilo,mega,giga etc.
	 */

	if (bytes < 5000*1024)
		buf[0] = 0;
	else if (prefix == IEC) {
		if (bytes < 2*1024LL*1024LL*1024LL) {
			long cMiB = (bytes * 200LL / (1LL<<20) +1) /2;
			snprintf(buf, sizeof(buf), "%ld.%02ldMiB",
				 cMiB/100, cMiB % 100);
		} else if (bytes < 2*1024LL*1024LL*1024LL*1024LL) {
			long cGiB = (bytes * 200LL / (1LL<<30) +1) /2;
			snprintf(buf, sizeof(buf), "%ld.%02ldGiB",
				 cGiB/100, cGiB % 100);
		} else {
			long cTiB = (bytes * 200LL / (1LL<<40) + 1) / 2;
			snprintf(buf, sizeof(buf), "%ld.%02ldTiB",
				 cTiB/100, cTiB % 100);
		}
	}
	else if (prefix == JEDEC) {
		if (bytes < 2*1024LL*1024LL*1024LL) {
			long cMB  = (bytes / ( 1000000LL / 200LL ) +1) /2;
			snprintf(buf, sizeof(buf), "%ld.%02ldMB",
				 cMB/100, cMB % 100);
		} else if (bytes < 2*1024LL*1024LL*1024LL*1024LL) {
			long cGB  = (bytes / (1000000000LL/200LL ) +1) /2;
			snprintf(buf, sizeof(buf), "%ld.%02ldGB",
				 cGB/100, cGB % 100);
		} else {
			long cTB  = (bytes / (1000000000000LL / 200LL) + 1) / 2;
			snprintf(buf, sizeof(buf), "%ld.%02ldTB",
				 cTB/100, cTB % 100);
		}
	}
	else
		buf[0] = 0;

	return buf;
}

void print_r10_layout(int layout)
{
	int near = layout & 255;
	int far = (layout >> 8) & 255;
	int offset = (layout&0x10000);
	char *sep = "";

	if (near != 1) {
		printf("%s near=%d", sep, near);
		sep = ",";
	}
	if (far != 1)
		printf("%s %s=%d", sep, offset?"offset":"far", far);
	if (near*far == 1)
		printf("NO REDUNDANCY");
}

unsigned long long calc_array_size(int level, int raid_disks, int layout,
				   int chunksize, unsigned long long devsize)
{
	if (level == 1)
		return devsize;
	devsize &= ~(unsigned long long)((chunksize>>9)-1);
	return get_data_disks(level, layout, raid_disks) * devsize;
}

int get_data_disks(int level, int layout, int raid_disks)
{
	int data_disks = 0;
	switch (level) {
	case 0: data_disks = raid_disks;
		break;
	case 1: data_disks = 1;
		break;
	case 4:
	case 5: data_disks = raid_disks - 1;
		break;
	case 6: data_disks = raid_disks - 2;
		break;
	case 10: data_disks = raid_disks / (layout & 255) / ((layout>>8)&255);
		break;
	}

	return data_disks;
}

dev_t devnm2devid(char *devnm)
{
	/* First look in /sys/block/$DEVNM/dev for %d:%d
	 * If that fails, try parsing out a number
	 */
	char path[PATH_MAX];
	char *ep;
	int fd;
	int mjr,mnr;

	snprintf(path, sizeof(path), "/sys/block/%s/dev", devnm);
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		char buf[20];
		int n = read(fd, buf, sizeof(buf));
		close(fd);
		if (n > 0)
			buf[n] = 0;
		if (n > 0 && sscanf(buf, "%d:%d\n", &mjr, &mnr) == 2)
			return makedev(mjr, mnr);
	}
	if (strncmp(devnm, "md_d", 4) == 0 &&
	    isdigit(devnm[4]) &&
	    (mnr = strtoul(devnm+4, &ep, 10)) >= 0 &&
	    ep > devnm && *ep == 0)
		return makedev(get_mdp_major(), mnr << MdpMinorShift);

	if (strncmp(devnm, "md", 2) == 0 &&
	    isdigit(devnm[2]) &&
	    (mnr = strtoul(devnm+2, &ep, 10)) >= 0 &&
	    ep > devnm && *ep == 0)
		return makedev(MD_MAJOR, mnr);

	return 0;
}

/**
 * is_devname_numbered() - helper for numbered devname verification.
 * @devname: path or name to check.
 * @pref: expected devname prefix.
 * @pref_len: prefix len.
 */
static bool is_devname_numbered(const char *devname, const char *pref, const int pref_len)
{
	int val;

	assert(devname && pref);

	if (strncmp(devname, pref, pref_len) != 0)
		return false;

	if (parse_num(&val, devname + pref_len) != 0)
		return false;

	/* Allow any number that represents a valid minor number */
	if (val >= (1 << 20))
		return false;

	return true;
}

/**
 * is_devname_md_numbered() - check if &devname is numbered MD device (md).
 * @devname: path or name to check.
 */
bool is_devname_md_numbered(const char *devname)
{
	return is_devname_numbered(devname, DEV_NUM_PREF, DEV_NUM_PREF_LEN);
}

/**
 * is_devname_md_d_numbered() - check if &devname is secondary numbered MD device (md_d).
 * @devname: path or name to check.
 */
bool is_devname_md_d_numbered(const char *devname)
{
	static const char d_dev[] = DEV_NUM_PREF "_d";

	return is_devname_numbered(devname, d_dev, sizeof(d_dev) - 1);
}

/**
 * get_md_name() - Get main dev node of the md device.
 * @devnm: Md device name or path.
 *
 * Function checks if the full name was passed and returns md name
 * if it is the MD device.
 *
 * Return: Main dev node of the md device or NULL if not found.
 */
char *get_md_name(char *devnm)
{
	static char devname[NAME_MAX];
	struct stat stb;

	if (strncmp(devnm, "/dev/", 5) == 0)
		snprintf(devname, sizeof(devname), "%s", devnm);
	else
		snprintf(devname, sizeof(devname), "/dev/%s", devnm);

	if (!is_mddev(devname))
		return NULL;
	if (stat(devname, &stb) == 0 && (S_IFMT&stb.st_mode) == S_IFBLK)
		return devname;

	return NULL;
}

void put_md_name(char *name)
{
	if (strncmp(name, "/dev/.tmp.md", 12) == 0)
		unlink(name);
}

int get_maj_min(char *dev, int *major, int *minor)
{
	char *e;
	*major = strtoul(dev, &e, 0);
	return (e > dev && *e == ':' && e[1] &&
		(*minor = strtoul(e+1, &e, 0)) >= 0 &&
		*e == 0);
}

/**
 * is_bit_set() - get bit value by index.
 * @val: value.
 * @index: index of the bit (LSB numbering).
 *
 * Return: bit value.
 */
bool is_bit_set(int *val, unsigned char index)
{
	if ((*val) & (1 << index))
		return true;
	return false;
}

int dev_open(char *dev, int flags)
{
	/* like 'open', but if 'dev' matches %d:%d, create a temp
	 * block device and open that
	 */
	int fd = -1;
	char devname[32];
	int major;
	int minor;

	if (!dev)
		return -1;
	flags |= O_DIRECT;

	if (get_maj_min(dev, &major, &minor)) {
		snprintf(devname, sizeof(devname), "/dev/.tmp.md.%d:%d:%d",
			 (int)getpid(), major, minor);
		if (mknod(devname, S_IFBLK|0600, makedev(major, minor)) == 0) {
			fd = open(devname, flags);
			unlink(devname);
		}
	} else
		fd = open(dev, flags);
	return fd;
}

int open_dev_flags(char *devnm, int flags)
{
	dev_t devid;
	char buf[20];

	devid = devnm2devid(devnm);
	sprintf(buf, "%d:%d", major(devid), minor(devid));
	return dev_open(buf, flags);
}

int open_dev(char *devnm)
{
	return open_dev_flags(devnm, O_RDONLY);
}

int open_dev_excl(char *devnm)
{
	char buf[20];
	int i;
	int flags = O_RDWR;
	dev_t devid = devnm2devid(devnm);
	unsigned int delay = 1; // miliseconds

	sprintf(buf, "%d:%d", major(devid), minor(devid));
	for (i = 0; i < 25; i++) {
		int fd = dev_open(buf, flags|O_EXCL);
		if (fd >= 0)
			return fd;
		if (errno == EACCES && flags == O_RDWR) {
			flags = O_RDONLY;
			continue;
		}
		if (errno != EBUSY)
			return fd;
		sleep_for(0, MSEC_TO_NSEC(delay), true);
		if (delay < 200)
			delay *= 2;
	}
	return -1;
}

int same_dev(char *one, char *two)
{
	struct stat st1, st2;
	if (stat(one, &st1) != 0)
		return 0;
	if (stat(two, &st2) != 0)
		return 0;
	if ((st1.st_mode & S_IFMT) != S_IFBLK)
		return 0;
	if ((st2.st_mode & S_IFMT) != S_IFBLK)
		return 0;
	return st1.st_rdev == st2.st_rdev;
}

void wait_for(char *dev, int fd)
{
	int i;
	struct stat stb_want;
	unsigned int delay = 1; // miliseconds

	if (fstat(fd, &stb_want) != 0 ||
	    (stb_want.st_mode & S_IFMT) != S_IFBLK)
		return;

	for (i = 0; i < 25; i++) {
		struct stat stb;
		if (stat(dev, &stb) == 0 &&
		    (stb.st_mode & S_IFMT) == S_IFBLK &&
		    (stb.st_rdev == stb_want.st_rdev))
			return;
		sleep_for(0, MSEC_TO_NSEC(delay), true);
		if (delay < 200)
			delay *= 2;
	}
	if (i == 25)
		pr_err("timeout waiting for %s\n", dev);
}

struct superswitch *superlist[] =
{
	&super0, &super1,
	&super_ddf, &super_imsm,
	&mbr, &gpt,
	NULL
};

struct supertype *super_by_fd(int fd, char **subarrayp)
{
	mdu_array_info_t array;
	int vers;
	int minor;
	struct supertype *st = NULL;
	struct mdinfo *sra;
	char *verstr;
	char version[20];
	int i;
	char *subarray = NULL;
	char container[32] = "";
	char *devnm = NULL;

	devnm = fd2devnm(fd);
	if (!devnm)
		return NULL;

	sra = sysfs_read(fd, NULL, GET_VERSION);

	if (sra) {
		vers = sra->array.major_version;
		minor = sra->array.minor_version;
		verstr = sra->text_version;
	} else {
		if (md_get_array_info(fd, &array))
			array.major_version = array.minor_version = 0;
		vers = array.major_version;
		minor = array.minor_version;
		verstr = "";
	}

	if (vers != -1) {
		sprintf(version, "%d.%d", vers, minor);
		verstr = version;
	}
	if (minor == -2 && is_subarray(verstr)) {
		char *dev = verstr+1;

		subarray = strchr(dev, '/');
		if (subarray) {
			*subarray++ = '\0';
			subarray = xstrdup(subarray);
		}
		snprintf(container, sizeof(container), "%s", dev);
		sysfs_free(sra);
		sra = sysfs_read(-1, container, GET_VERSION);
		if (sra && sra->text_version[0])
			verstr = sra->text_version;
		else
			verstr = "-no-metadata-";
	}

	for (i = 0; st == NULL && superlist[i]; i++)
		st = superlist[i]->match_metadata_desc(verstr);

	sysfs_free(sra);
	if (st) {
		st->sb = NULL;
		if (subarrayp)
			*subarrayp = subarray;
		strcpy(st->container_devnm, container);
		strncpy(st->devnm, devnm, MD_NAME_MAX - 1);
	} else
		free(subarray);

	return st;
}

struct supertype *dup_super(struct supertype *orig)
{
	struct supertype *st;

	if (!orig)
		return orig;
	st = xcalloc(1, sizeof(*st));
	st->ss = orig->ss;
	st->max_devs = orig->max_devs;
	st->minor_version = orig->minor_version;
	st->ignore_hw_compat = orig->ignore_hw_compat;
	st->data_offset = orig->data_offset;
	st->sb = NULL;
	st->info = NULL;
	return st;
}

struct supertype *guess_super_type(int fd, enum guess_types guess_type)
{
	/* try each load_super to find the best match,
	 * and return the best superswitch
	 */
	struct superswitch  *ss;
	struct supertype *st;
	unsigned int besttime = 0;
	int bestsuper = -1;
	int i;

	st = xcalloc(1, sizeof(*st));
	st->container_devnm[0] = 0;

	for (i = 0; superlist[i]; i++) {
		int rv;
		ss = superlist[i];
		if (guess_type == guess_array && ss->add_to_super == NULL)
			continue;
		if (guess_type == guess_partitions && ss->add_to_super != NULL)
			continue;
		memset(st, 0, sizeof(*st));
		st->ignore_hw_compat = 1;
		rv = ss->load_super(st, fd, NULL);
		if (rv == 0) {
			struct mdinfo info;
			st->ss->getinfo_super(st, &info, NULL);
			if (bestsuper == -1 ||
			    besttime < info.array.ctime) {
				bestsuper = i;
				besttime = info.array.ctime;
			}
			ss->free_super(st);
		}
	}
	if (bestsuper != -1) {
		int rv;
		memset(st, 0, sizeof(*st));
		st->ignore_hw_compat = 1;
		rv = superlist[bestsuper]->load_super(st, fd, NULL);
		if (rv == 0) {
			superlist[bestsuper]->free_super(st);
			return st;
		}
	}
	free(st);
	return NULL;
}

/* Return size of device in bytes */
int get_dev_size(int fd, char *dname, unsigned long long *sizep)
{
	unsigned long long ldsize;
	struct stat st;

	if (fstat(fd, &st) != -1 && S_ISREG(st.st_mode))
		ldsize = (unsigned long long)st.st_size;
	else
#ifdef BLKGETSIZE64
	if (ioctl(fd, BLKGETSIZE64, &ldsize) != 0)
#endif
	{
		unsigned long dsize;
		if (ioctl(fd, BLKGETSIZE, &dsize) == 0) {
			ldsize = dsize;
			ldsize <<= 9;
		} else {
			if (dname)
				pr_err("Cannot get size of %s: %s\n",
					dname, strerror(errno));
			return 0;
		}
	}
	*sizep = ldsize;
	return 1;
}

/* Return sector size of device in bytes */
int get_dev_sector_size(int fd, char *dname, unsigned int *sectsizep)
{
	unsigned int sectsize;

	if (ioctl(fd, BLKSSZGET, &sectsize) != 0) {
		if (dname)
			pr_err("Cannot get sector size of %s: %s\n",
				dname, strerror(errno));
		return 0;
	}

	*sectsizep = sectsize;
	return 1;
}

/* Return true if this can only be a container, not a member device.
 * i.e. is and md device and size is zero
 */
int must_be_container(int fd)
{
	struct mdinfo *mdi;
	unsigned long long size;

	mdi = sysfs_read(fd, NULL, GET_VERSION);
	if (!mdi)
		return 0;
	sysfs_free(mdi);

	if (get_dev_size(fd, NULL, &size) == 0)
		return 1;
	if (size == 0)
		return 1;
	return 0;
}

/* Sets endofpart parameter to the last block used by the last GPT partition on the device.
 * Returns: 1 if successful
 *         -1 for unknown partition type
 *          0 for other errors
 */
static int get_gpt_last_partition_end(int fd, unsigned long long *endofpart)
{
	struct GPT gpt;
	unsigned char empty_gpt_entry[16]= {0};
	struct GPT_part_entry *part;
	char buf[512];
	unsigned long long curr_part_end;
	unsigned all_partitions, entry_size;
	unsigned part_nr;
	unsigned int sector_size = 0;

	*endofpart = 0;

	BUILD_BUG_ON(sizeof(gpt) != 512);
	/* skip protective MBR */
	if (!get_dev_sector_size(fd, NULL, &sector_size))
		return 0;
	if (lseek(fd, sector_size, SEEK_SET) == -1L)
		return 0;
	/* read GPT header */
	if (read(fd, &gpt, 512) != 512)
		return 0;

	/* get the number of partition entries and the entry size */
	all_partitions = __le32_to_cpu(gpt.part_cnt);
	entry_size = __le32_to_cpu(gpt.part_size);

	/* Check GPT signature*/
	if (gpt.magic != GPT_SIGNATURE_MAGIC)
		return -1;

	/* sanity checks */
	if (all_partitions > 1024 ||
	    entry_size > sizeof(buf))
		return -1;

	part = (struct GPT_part_entry *)buf;

	/* set offset to third block (GPT entries) */
	if (lseek(fd, sector_size*2, SEEK_SET) == -1L)
		return 0;
	for (part_nr = 0; part_nr < all_partitions; part_nr++) {
		/* read partition entry */
		if (read(fd, buf, entry_size) != (ssize_t)entry_size)
			return 0;

		/* is this valid partition? */
		if (memcmp(part->type_guid, empty_gpt_entry, 16) != 0) {
			/* check the last lba for the current partition */
			curr_part_end = __le64_to_cpu(part->ending_lba);
			if (curr_part_end > *endofpart)
				*endofpart = curr_part_end;
		}

	}
	return 1;
}

/* Sets endofpart parameter to the last block used by the last partition on the device.
 * Returns: 1 if successful
 *         -1 for unknown partition type
 *          0 for other errors
 */
static int get_last_partition_end(int fd, unsigned long long *endofpart)
{
	struct MBR boot_sect;
	unsigned long long curr_part_end;
	unsigned part_nr;
	unsigned int sector_size;
	int retval = 0;

	*endofpart = 0;

	BUILD_BUG_ON(sizeof(boot_sect) != 512);
	/* read MBR */
	if (lseek(fd, 0, 0) == -1L)
		goto abort;
	if (read(fd, &boot_sect, 512) != 512)
		goto abort;

	/* check MBP signature */
	if (boot_sect.magic == MBR_SIGNATURE_MAGIC) {
		retval = 1;
		/* found the correct signature */

		for (part_nr = 0; part_nr < MBR_PARTITIONS; part_nr++) {
			/*
			 * Have to make every access through boot_sect rather
			 * than using a pointer to the partition table (or an
			 * entry), since the entries are not properly aligned.
			 */

			/* check for GPT type */
			if (boot_sect.parts[part_nr].part_type ==
			    MBR_GPT_PARTITION_TYPE) {
				retval = get_gpt_last_partition_end(fd, endofpart);
				break;
			}
			/* check the last used lba for the current partition  */
			curr_part_end =
				__le32_to_cpu(boot_sect.parts[part_nr].first_sect_lba) +
				__le32_to_cpu(boot_sect.parts[part_nr].blocks_num);
			if (curr_part_end > *endofpart)
				*endofpart = curr_part_end;
		}
	} else {
		/* Unknown partition table */
		retval = -1;
	}
	/* calculate number of 512-byte blocks */
	if (get_dev_sector_size(fd, NULL, &sector_size))
		*endofpart *= (sector_size / 512);
 abort:
	return retval;
}

int check_partitions(int fd, char *dname, unsigned long long freesize,
			unsigned long long size)
{
	/*
	 * Check where the last partition ends
	 */
	unsigned long long endofpart;

	if (get_last_partition_end(fd, &endofpart) > 0) {
		/* There appears to be a partition table here */
		if (freesize == 0) {
			/* partitions will not be visible in new device */
			pr_err("partition table exists on %s but will be lost or\n"
			       "       meaningless after creating array\n",
			       dname);
			return 1;
		} else if (endofpart > freesize) {
			/* last partition overlaps metadata */
			pr_err("metadata will over-write last partition on %s.\n",
			       dname);
			return 1;
		} else if (size && endofpart > size) {
			/* partitions will be truncated in new device */
			pr_err("array size is too small to cover all partitions on %s.\n",
			       dname);
			return 1;
		}
	}
	return 0;
}

int open_container(int fd)
{
	/* 'fd' is a block device.  Find out if it is in use
	 * by a container, and return an open fd on that container.
	 */
	char path[288];
	char *e;
	DIR *dir;
	struct dirent *de;
	int dfd, n;
	char buf[200];
	int major, minor;
	struct stat st;

	if (fstat(fd, &st) != 0)
		return -1;
	sprintf(path, "/sys/dev/block/%d:%d/holders",
		(int)major(st.st_rdev), (int)minor(st.st_rdev));
	e = path + strlen(path);

	dir = opendir(path);
	if (!dir)
		return -1;
	while ((de = readdir(dir))) {
		if (de->d_ino == 0)
			continue;
		if (de->d_name[0] == '.')
			continue;
		/* Need to make sure it is a container and not a volume */
		sprintf(e, "/%s/md/metadata_version", de->d_name);
		dfd = open(path, O_RDONLY);
		if (dfd < 0)
			continue;
		n = read(dfd, buf, sizeof(buf));
		close(dfd);
		if (n <= 0 || (unsigned)n >= sizeof(buf))
			continue;
		buf[n] = 0;
		if (strncmp(buf, "external", 8) != 0 ||
		    n < 10 ||
		    buf[9] == '/')
			continue;
		sprintf(e, "/%s/dev", de->d_name);
		dfd = open(path, O_RDONLY);
		if (dfd < 0)
			continue;
		n = read(dfd, buf, sizeof(buf));
		close(dfd);
		if (n <= 0 || (unsigned)n >= sizeof(buf))
			continue;
		buf[n] = 0;
		if (sscanf(buf, "%d:%d", &major, &minor) != 2)
			continue;
		sprintf(buf, "%d:%d", major, minor);
		dfd = dev_open(buf, O_RDONLY);
		if (dfd >= 0) {
			closedir(dir);
			return dfd;
		}
	}
	closedir(dir);
	return -1;
}

struct superswitch *version_to_superswitch(char *vers)
{
	int i;

	for (i = 0; superlist[i]; i++) {
		struct superswitch *ss = superlist[i];

		if (strcmp(vers, ss->name) == 0)
			return ss;
	}

	return NULL;
}

int metadata_container_matches(char *metadata, char *devnm)
{
	/* Check if 'devnm' is the container named in 'metadata'
	 * which is
	 *   /containername/componentname  or
	 *   -containername/componentname
	 */
	int l;
	if (*metadata != '/' && *metadata != '-')
		return 0;
	l = strlen(devnm);
	if (strncmp(metadata+1, devnm, l) != 0)
		return 0;
	if (metadata[l+1] != '/')
		return 0;
	return 1;
}

int metadata_subdev_matches(char *metadata, char *devnm)
{
	/* Check if 'devnm' is the subdev named in 'metadata'
	 * which is
	 *   /containername/subdev  or
	 *   -containername/subdev
	 */
	char *sl;
	if (*metadata != '/' && *metadata != '-')
		return 0;
	sl = strchr(metadata+1, '/');
	if (!sl)
		return 0;
	if (strcmp(sl+1, devnm) == 0)
		return 1;
	return 0;
}

int is_subarray_active(char *subarray, char *container)
{
	struct mdstat_ent *mdstat = mdstat_read(0, 0);
	struct mdstat_ent *ent;

	for (ent = mdstat; ent; ent = ent->next)
		if (is_container_member(ent, container))
			if (strcmp(to_subarray(ent, container), subarray) == 0)
				break;

	free_mdstat(mdstat);

	return ent != NULL;
}

/* open_subarray - opens a subarray in a container
 * @dev: container device name
 * @st: empty supertype
 * @quiet: block reporting errors flag
 *
 * On success returns an fd to a container and fills in *st
 */
int open_subarray(char *dev, char *subarray, struct supertype *st, int quiet)
{
	struct mdinfo *mdi;
	struct mdinfo *info;
	int fd, err = 1;
	char *_devnm;

	fd = open(dev, O_RDWR|O_EXCL);
	if (fd < 0) {
		if (!quiet)
			pr_err("Couldn't open %s, aborting\n",
				dev);
		return -1;
	}

	_devnm = fd2devnm(fd);
	if (_devnm == NULL) {
		if (!quiet)
			pr_err("Failed to determine device number for %s\n",
			       dev);
		goto close_fd;
	}
	snprintf(st->devnm, sizeof(st->devnm), "%s", _devnm);

	mdi = sysfs_read(fd, st->devnm, GET_VERSION|GET_LEVEL);
	if (!mdi) {
		if (!quiet)
			pr_err("Failed to read sysfs for %s\n",
				dev);
		goto close_fd;
	}

	if (mdi->array.level != UnSet) {
		if (!quiet)
			pr_err("%s is not a container\n", dev);
		goto free_sysfs;
	}

	st->ss = version_to_superswitch(mdi->text_version);
	if (!st->ss) {
		if (!quiet)
			pr_err("Operation not supported for %s metadata\n",
			       mdi->text_version);
		goto free_sysfs;
	}

	if (st->devnm[0] == 0) {
		if (!quiet)
			pr_err("Failed to allocate device name\n");
		goto free_sysfs;
	}

	if (!st->ss->load_container) {
		if (!quiet)
			pr_err("%s is not a container\n", dev);
		goto free_sysfs;
	}

	if (st->ss->load_container(st, fd, NULL)) {
		if (!quiet)
			pr_err("Failed to load metadata for %s\n",
				dev);
		goto free_sysfs;
	}

	info = st->ss->container_content(st, subarray);
	if (!info) {
		if (!quiet)
			pr_err("Failed to find subarray-%s in %s\n",
				subarray, dev);
		goto free_super;
	}
	free(info);

	err = 0;

 free_super:
	if (err)
		st->ss->free_super(st);
 free_sysfs:
	sysfs_free(mdi);
 close_fd:
	if (err)
		close(fd);

	if (err)
		return -1;
	else
		return fd;
}

int add_disk(int mdfd, struct supertype *st,
	     struct mdinfo *sra, struct mdinfo *info)
{
	/* Add a device to an array, in one of 2 ways. */
	int rv;

	if (st->ss->external) {
		if (info->disk.state & (1<<MD_DISK_SYNC))
			info->recovery_start = MaxSector;
		else
			info->recovery_start = 0;
		rv = sysfs_add_disk(sra, info, 0);
		if (! rv) {
			struct mdinfo *sd2;
			for (sd2 = sra->devs; sd2; sd2=sd2->next)
				if (sd2 == info)
					break;
			if (sd2 == NULL) {
				sd2 = xmalloc(sizeof(*sd2));
				*sd2 = *info;
				sd2->next = sra->devs;
				sra->devs = sd2;
			}
		}
	} else
		rv = ioctl(mdfd, ADD_NEW_DISK, &info->disk);
	return rv;
}

int remove_disk(int mdfd, struct supertype *st,
		struct mdinfo *sra, struct mdinfo *info)
{
	int rv;

	/* Remove the disk given by 'info' from the array */
	if (st->ss->external)
		rv = sysfs_set_str(sra, info, "slot", STR_COMMON_NONE);
	else
		rv = ioctl(mdfd, HOT_REMOVE_DISK, makedev(info->disk.major,
							  info->disk.minor));
	return rv;
}

int hot_remove_disk(int mdfd, unsigned long dev, int force)
{
	int cnt = force ? 500 : 5;
	int ret;

	/* HOT_REMOVE_DISK can fail with EBUSY if there are
	 * outstanding IO requests to the device.
	 * In this case, it can be helpful to wait a little while,
	 * up to 5 seconds if 'force' is set, or 50 msec if not.
	 */
	while ((ret = ioctl(mdfd, HOT_REMOVE_DISK, dev)) == -1 &&
	       errno == EBUSY &&
	       cnt-- > 0)
		sleep_for(0, MSEC_TO_NSEC(10), true);

	return ret;
}

int sys_hot_remove_disk(int statefd, int force)
{
	int cnt = force ? 500 : 5;

	while (cnt--) {
		int err = 0;
		int ret = sysfs_set_memb_state_fd(statefd, MEMB_STATE_REMOVE, &err);

		if (ret == MDADM_STATUS_SUCCESS)
			return 0;

		if (err != EBUSY)
			break;

		sleep_for(0, MSEC_TO_NSEC(10), true);
	}

	return -1;
}

int set_array_info(int mdfd, struct supertype *st, struct mdinfo *info)
{
	/* Initialise kernel's knowledge of array.
	 * This varies between externally managed arrays
	 * and older kernels
	 */
	mdu_array_info_t inf;
	int rv;

	if (st->ss->external)
		return sysfs_set_array(info);

	memset(&inf, 0, sizeof(inf));
	inf.major_version = info->array.major_version;
	inf.minor_version = info->array.minor_version;
	rv = md_set_array_info(mdfd, &inf);

	return rv;
}

unsigned long long min_recovery_start(struct mdinfo *array)
{
	/* find the minimum recovery_start in an array for metadata
	 * formats that only record per-array recovery progress instead
	 * of per-device
	 */
	unsigned long long recovery_start = MaxSector;
	struct mdinfo *d;

	for (d = array->devs; d; d = d->next)
		recovery_start = min(recovery_start, d->recovery_start);

	return recovery_start;
}

int mdmon_pid(const char *devnm)
{
	char path[100];
	char pid[10];
	int fd;
	int n;

	sprintf(path, "%s/%s.pid", MDMON_DIR, devnm);

	fd = open(path, O_RDONLY | O_NOATIME, 0);

	if (fd < 0)
		return -1;
	n = read(fd, pid, 9);
	close(fd);
	if (n <= 0)
		return -1;
	return atoi(pid);
}

int mdmon_running(const char *devnm)
{
	int pid = mdmon_pid(devnm);
	if (pid <= 0)
		return 0;
	if (kill(pid, 0) == 0)
		return 1;
	return 0;
}

/*
 * wait_for_mdmon_control_socket() - Waits for mdmon control socket
 * to be created within specified time.
 * @container_devnm: Device for which mdmon control socket should start.
 *
 * In foreground mode, when mdadm is trying to connect to control
 * socket it is possible that the mdmon has not created it yet.
 * Give some time to mdmon to create socket. Timeout set to 2 sec.
 *
 * Return: MDADM_STATUS_SUCCESS if connect succeed, otherwise return
 * error code.
 */
mdadm_status_t wait_for_mdmon_control_socket(const char *container_devnm)
{
	enum mdadm_status status = MDADM_STATUS_SUCCESS;
	int sfd, rv, retry_count = 0;
	struct sockaddr_un addr;
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%s.sock", MDMON_DIR, container_devnm);
	sfd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (!is_fd_valid(sfd))
		return MDADM_STATUS_ERROR;

	addr.sun_family = PF_LOCAL;
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
        addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

	for (retry_count = 0; retry_count < 10; retry_count++) {
		rv = connect(sfd, (struct sockaddr*)&addr, sizeof(addr));
		if (rv < 0) {
			sleep_for(0, MSEC_TO_NSEC(200), true);
			continue;
		}
		break;
	}

	if (rv < 0) {
		pr_err("Failed to connect to control socket.\n");
		status = MDADM_STATUS_ERROR;
	}
	close(sfd);
	return status;
}

/*
 * wait_for_mdmon() - Waits for mdmon within specified time.
 * @devnm: Device for which mdmon should start.
 *
 * Function waits for mdmon to start. It may need few seconds
 * to start, we set timeout to 5, it should be sufficient.
 * Do not wait if mdmon has been started.
 *
 * Return: MDADM_STATUS_SUCCESS if mdmon is running, error code otherwise.
 */
mdadm_status_t wait_for_mdmon(const char *devnm)
{
	const time_t mdmon_timeout = 5;
	time_t start_time = time(0);

	if (mdmon_running(devnm))
		return MDADM_STATUS_SUCCESS;

	pr_info("Waiting for mdmon to start\n");
	while (time(0) - start_time < mdmon_timeout) {
		sleep_for(0, MSEC_TO_NSEC(200), true);
		if (mdmon_running(devnm))
			return MDADM_STATUS_SUCCESS;
	};

	pr_err("Timeout waiting for mdmon\n");
	return MDADM_STATUS_ERROR;
}

int start_mdmon(char *devnm)
{
	int i;
	int len;
	pid_t pid;
	int status;
	char *prefix = in_initrd() ? "initrd-" : "";
	char pathbuf[1024];
	char *paths[4] = {
		pathbuf,
		BINDIR "/mdmon",
		"./mdmon",
		NULL
	};

	if (check_env("MDADM_NO_MDMON"))
		return 0;
	if (continue_via_systemd(devnm, MDMON_SERVICE, prefix) == MDADM_STATUS_SUCCESS)
		return 0;

	/* That failed, try running mdmon directly */
	len = readlink("/proc/self/exe", pathbuf, sizeof(pathbuf)-1);
	if (len > 0) {
		char *sl;
		pathbuf[len] = 0;
		sl = strrchr(pathbuf, '/');
		if (sl)
			sl++;
		else
			sl = pathbuf;
		strcpy(sl, "mdmon");
	} else
		pathbuf[0] = '\0';

	switch(fork()) {
	case 0:
		manage_fork_fds(1);
		for (i = 0; paths[i]; i++)
			if (paths[i][0]) {
				execl(paths[i], paths[i],
				      devnm, NULL);
			}
		exit(1);
	case -1: pr_err("cannot run mdmon. Array remains readonly\n");
		return -1;
	default: /* parent - good */
		pid = wait(&status);
		if (pid < 0 || status != 0) {
			pr_err("failed to launch mdmon. Array remains readonly\n");
			return -1;
		}
	}
	return 0;
}

__u32 random32(void)
{
	__u32 rv;
	int rfd = open("/dev/urandom", O_RDONLY);
	if (rfd < 0 || read(rfd, &rv, 4) != 4)
		rv = random();
	if (rfd >= 0)
		close(rfd);
	return rv;
}

void random_uuid(__u8 *buf)
{
	int fd, i, len;
	__u32 r[4];

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		goto use_random;
	len = read(fd, buf, 16);
	close(fd);
	if (len != 16)
		goto use_random;

	return;

use_random:
	for (i = 0; i < 4; i++)
		r[i] = random();
	memcpy(buf, r, 16);
}

int flush_metadata_updates(struct supertype *st)
{
	int sfd;
	if (!st->updates) {
		st->update_tail = NULL;
		return -1;
	}

	sfd = connect_monitor(st->container_devnm);
	if (sfd < 0)
		return -1;

	while (st->updates) {
		struct metadata_update *mu = st->updates;
		st->updates = mu->next;

		send_message(sfd, mu, 0);
		wait_reply(sfd, 0);
		free(mu->buf);
		free(mu);
	}
	ack(sfd, 0);
	wait_reply(sfd, 0);
	close(sfd);
	st->update_tail = NULL;
	return 0;
}

void append_metadata_update(struct supertype *st, void *buf, int len)
{

	struct metadata_update *mu = xmalloc(sizeof(*mu));

	mu->buf = buf;
	mu->len = len;
	mu->space = NULL;
	mu->space_list = NULL;
	mu->next = NULL;
	*st->update_tail = mu;
	st->update_tail = &mu->next;
}

#ifdef __TINYC__
/* tinyc doesn't optimize this check in ioctl.h out ... */
unsigned int __invalid_size_argument_for_IOC = 0;
#endif

/**
 * disk_fd_matches_criteria() - check if device matches spare criteria.
 * @st: supertype, not NULL.
 * @disk_fd: file descriptor of the disk.
 * @sc: criteria to test.
 *
 * Return: true if disk matches criteria, false otherwise.
 */
bool disk_fd_matches_criteria(struct supertype *st, int disk_fd, struct spare_criteria *sc)
{
	unsigned int dev_sector_size = 0;
	unsigned long long dev_size = 0;

	if (!sc->criteria_set)
		return true;

	if (!get_dev_size(disk_fd, NULL, &dev_size) || dev_size < sc->min_size)
		return false;

	if (!get_dev_sector_size(disk_fd, NULL, &dev_sector_size) ||
	    sc->sector_size != dev_sector_size)
		return false;

	if (drive_test_and_add_policies(st, &sc->pols, disk_fd, 0))
		return false;

	return true;
}

/**
 * devid_matches_criteria() - check if device referenced by devid matches spare criteria.
 * @st: supertype, not NULL.
 * @devid: devid of the device to check.
 * @sc: criteria to test.
 *
 * Return: true if disk matches criteria, false otherwise.
 */
bool devid_matches_criteria(struct supertype *st, dev_t devid, struct spare_criteria *sc)
{
	char buf[NAME_MAX];
	bool ret;
	int fd;

	if (!sc->criteria_set)
		return true;

	snprintf(buf, NAME_MAX, "%d:%d", major(devid), minor(devid));

	fd = dev_open(buf, O_RDONLY);
	if (!is_fd_valid(fd))
		return false;

	/* Error code inherited */
	ret = disk_fd_matches_criteria(st, fd, sc);

	close(fd);
	return ret;
}

/* Pick all spares matching given criteria from a container
 * if min_size == 0 do not check size
 * if domlist == NULL do not check domains
 * if spare_group given add it to domains of each spare
 * metadata allows to test domains using metadata of destination array */
struct mdinfo *container_choose_spares(struct supertype *st,
				       struct spare_criteria *criteria,
				       struct domainlist *domlist,
				       char *spare_group,
				       const char *metadata, int get_one)
{
	struct mdinfo *d, **dp, *disks = NULL;

	/* get list of all disks in container */
	if (st->ss->getinfo_super_disks)
		disks = st->ss->getinfo_super_disks(st);

	if (!disks)
		return disks;
	/* find spare devices on the list */
	dp = &disks->devs;
	disks->array.spare_disks = 0;
	while (*dp) {
		bool found = false;

		d = *dp;
		if (d->disk.state == 0) {
			dev_t dev = makedev(d->disk.major,d->disk.minor);

			found = devid_matches_criteria(st, dev, criteria);

			/* check if domain matches */
			if (found && domlist) {
				struct dev_policy *pol = devid_policy(dev);
				if (spare_group)
					pol_add(&pol, pol_domain,
						spare_group, NULL);
				if (domain_test(domlist, pol, metadata) != 1)
					found = false;

				dev_policy_free(pol);
			}
		}
		if (found) {
			dp = &d->next;
			disks->array.spare_disks++;
			if (get_one) {
				sysfs_free(*dp);
				d->next = NULL;
			}
		} else {
			*dp = d->next;
			d->next = NULL;
			sysfs_free(d);
		}
	}
	return disks;
}

/* Checks if paths point to the same device
 * Returns 0 if they do.
 * Returns 1 if they don't.
 * Returns -1 if something went wrong,
 * e.g. paths are empty or the files
 * they point to don't exist */
int compare_paths (char* path1, char* path2)
{
	struct stat st1,st2;

	if (path1 == NULL || path2 == NULL)
		return -1;
	if (stat(path1,&st1) != 0)
		return -1;
	if (stat(path2,&st2) != 0)
		return -1;
	if ((st1.st_ino == st2.st_ino) && (st1.st_dev == st2.st_dev))
		return 0;
	return 1;
}

/* Make sure we can open as many devices as needed */
void enable_fds(int devices)
{
	unsigned int fds = 20 + devices;
	struct rlimit lim;
	if (getrlimit(RLIMIT_NOFILE, &lim) != 0 || lim.rlim_cur >= fds)
		return;
	if (lim.rlim_max < fds)
		lim.rlim_max = fds;
	lim.rlim_cur = fds;
	setrlimit(RLIMIT_NOFILE, &lim);
}

/* Close all opened descriptors if needed and redirect
 * streams to /dev/null.
 * For debug purposed, leave STDOUT and STDERR untouched
 * Returns:
 *	1- if any error occurred
 *	0- otherwise
 */
void manage_fork_fds(int close_all)
{
	DIR *dir;
	struct dirent *dirent;
	int fd = open("/dev/null", O_RDWR);

	if (is_fd_valid(fd)) {
		dup2(fd, 0);
#ifndef DEBUG
	dup2(0, 1);
	dup2(0, 2);
	close_fd(&fd);
#endif
	}

	if (close_all == 0)
		return;

	dir = opendir("/proc/self/fd");
	if (!dir) {
		pr_err("Cannot open /proc/self/fd directory.\n");
		return;
	}
	for (dirent = readdir(dir); dirent; dirent = readdir(dir)) {
		int fd = -1;

		if ((strcmp(dirent->d_name, ".") == 0) ||
		    (strcmp(dirent->d_name, "..")) == 0)
			continue;

		fd = strtol(dirent->d_name, NULL, 10);
		if (fd > 2)
			close_fd(&fd);
	}
	closedir(dir);
	return;
}

/* In a systemd/udev world, it is best to get systemd to
 * run daemon rather than running in the background.
 * Returns:
 *	MDADM_STATUS_SUCCESS - if systemd service has been started.
 *	MDADM_STATUS_ERROR - otherwise.
 */
mdadm_status_t continue_via_systemd(char *devnm, char *service_name, char *prefix)
{
	int pid, status;
	char pathbuf[PATH_MAX];

	dprintf("Start %s service\n", service_name);
	/* Simply return that service cannot be started */
	if (check_env("MDADM_NO_SYSTEMCTL"))
		return MDADM_STATUS_ERROR;

	/* Fork in attempt to start services */
	switch (fork()) {
	case -1: /* Fork failed, just do it ourselves. */
		break;
	case  0: /* child */
		manage_fork_fds(1);
		snprintf(pathbuf, sizeof(pathbuf), "%s@%s%s.service",
			 service_name, prefix ? prefix : "", devnm);

		/* Attempt to start service.
		 * On success execl() will "kill" the fork, and return status of systemctl call.
		 */
		execl("/usr/bin/systemctl", "systemctl", "restart", pathbuf, NULL);
		execl("/bin/systemctl", "systemctl", "restart", pathbuf, NULL);
		exit(MDADM_STATUS_ERROR);
	default: /* parent */
		/* Check if forked process successfully trigered service */
		pid = wait(&status);
		if (pid >= 0 && status == 0)
			return MDADM_STATUS_SUCCESS;
	}
	return MDADM_STATUS_ERROR;
}

int in_initrd(void)
{
	return access("/etc/initrd-release", F_OK) >= 0;
}

void reopen_mddev(int mdfd)
{
	/* Re-open without any O_EXCL, but keep
	 * the same fd
	 */
	char *devnm = fd2devnm(mdfd);
	int fd = open_dev(devnm);

	if (!is_fd_valid(fd))
		return;

	dup2(fd, mdfd);

	close_fd(&fd);
}

static struct cmap_hooks *cmap_hooks = NULL;
static int is_cmap_hooks_ready = 0;

void set_cmap_hooks(void)
{
	cmap_hooks = xmalloc(sizeof(struct cmap_hooks));
	cmap_hooks->cmap_handle = dlopen("libcmap.so.4", RTLD_NOW | RTLD_LOCAL);
	if (!cmap_hooks->cmap_handle)
		return;

	cmap_hooks->initialize =
		dlsym(cmap_hooks->cmap_handle, "cmap_initialize");
	cmap_hooks->get_string =
		dlsym(cmap_hooks->cmap_handle, "cmap_get_string");
	cmap_hooks->finalize = dlsym(cmap_hooks->cmap_handle, "cmap_finalize");

	if (!cmap_hooks->initialize || !cmap_hooks->get_string ||
	    !cmap_hooks->finalize)
		dlclose(cmap_hooks->cmap_handle);
	else
		is_cmap_hooks_ready = 1;
}

int get_cluster_name(char **cluster_name)
{
        int rv = -1;
	cmap_handle_t handle;

	if (!is_cmap_hooks_ready)
		return rv;

        rv = cmap_hooks->initialize(&handle);
        if (rv != CS_OK)
                goto out;

        rv = cmap_hooks->get_string(handle, "totem.cluster_name", cluster_name);
        if (rv != CS_OK) {
                free(*cluster_name);
                rv = -1;
                goto name_err;
        }

        rv = 0;
name_err:
        cmap_hooks->finalize(handle);
out:
        return rv;
}

void set_dlm_hooks(void)
{
	dlm_hooks = xmalloc(sizeof(struct dlm_hooks));
	dlm_hooks->dlm_handle = dlopen("libdlm_lt.so.3", RTLD_NOW | RTLD_LOCAL);
	if (!dlm_hooks->dlm_handle)
		return;

	dlm_hooks->open_lockspace =
		dlsym(dlm_hooks->dlm_handle, "dlm_open_lockspace");
	dlm_hooks->create_lockspace =
		dlsym(dlm_hooks->dlm_handle, "dlm_create_lockspace");
	dlm_hooks->release_lockspace =
		dlsym(dlm_hooks->dlm_handle, "dlm_release_lockspace");
	dlm_hooks->ls_lock = dlsym(dlm_hooks->dlm_handle, "dlm_ls_lock");
	dlm_hooks->ls_unlock_wait =
		dlsym(dlm_hooks->dlm_handle, "dlm_ls_unlock_wait");
	dlm_hooks->ls_get_fd = dlsym(dlm_hooks->dlm_handle, "dlm_ls_get_fd");
	dlm_hooks->dispatch = dlsym(dlm_hooks->dlm_handle, "dlm_dispatch");

	if (!dlm_hooks->open_lockspace || !dlm_hooks->create_lockspace ||
	    !dlm_hooks->ls_lock || !dlm_hooks->ls_unlock_wait ||
	    !dlm_hooks->release_lockspace || !dlm_hooks->ls_get_fd ||
	    !dlm_hooks->dispatch)
		dlclose(dlm_hooks->dlm_handle);
	else
		is_dlm_hooks_ready = 1;
}

void set_hooks(void)
{
	set_dlm_hooks();
	set_cmap_hooks();
}

int zero_disk_range(int fd, unsigned long long sector, size_t count)
{
	int ret = 0;
	int fd_zero;
	void *addr = NULL;
	size_t written = 0;
	size_t len = count * 512;
	ssize_t n;

	fd_zero = open("/dev/zero", O_RDONLY);
	if (fd_zero < 0) {
		pr_err("Cannot open /dev/zero\n");
		return -1;
	}

	if (lseek64(fd, sector * 512, SEEK_SET) < 0) {
		ret = -errno;
		pr_err("Failed to seek offset for zeroing\n");
		goto out;
	}

	addr = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd_zero, 0);

	if (addr == MAP_FAILED) {
		ret = -errno;
		pr_err("Mapping /dev/zero failed\n");
		goto out;
	}

	do {
		n = write(fd, addr + written, len - written);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			pr_err("Zeroing disk range failed\n");
			break;
		}
		written += n;
	} while (written != len);

	munmap(addr, len);

out:
	close(fd_zero);
	return ret;
}

/**
 * sleep_for() - Sleeps for specified time.
 * @sec: Seconds to sleep for.
 * @nsec: Nanoseconds to sleep for, has to be less than one second.
 * @wake_after_interrupt: If set, wake up if interrupted.
 *
 * Function immediately returns if error different than EINTR occurs.
 */
void sleep_for(unsigned int sec, long nsec, bool wake_after_interrupt)
{
	struct timespec delay = {.tv_sec = sec, .tv_nsec = nsec};

	assert(nsec < MSEC_TO_NSEC(1000));

	do {
		errno = 0;
		nanosleep(&delay, &delay);
		if (errno != 0 && errno != EINTR) {
			pr_err("Error sleeping for %us %ldns: %s\n", sec, nsec, strerror(errno));
			return;
		}
	} while (!wake_after_interrupt && errno == EINTR);
}

/* is_directory() - Checks if directory provided by path is indeed a regular directory.
 * @path: directory path to be checked
 *
 * Doesn't accept symlinks.
 *
 * Return: true if is a directory, false if not
 */
bool is_directory(const char *path)
{
	struct stat st;

	if (lstat(path, &st) != 0) {
		pr_err("%s: %s\n", strerror(errno), path);
		return false;
	}

	if (!S_ISDIR(st.st_mode))
		return false;

	return true;
}

/*
 * is_file() - Checks if file provided by path is indeed a regular file.
 * @path: file path to be checked
 *
 * Doesn't accept symlinks.
 *
 * Return: true if is  a file, false if not
 */
bool is_file(const char *path)
{
	struct stat st;

	if (lstat(path, &st) != 0) {
		pr_err("%s: %s\n", strerror(errno), path);
		return false;
	}

	if (!S_ISREG(st.st_mode))
		return false;

	return true;
}
