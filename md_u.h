/*
   md_u.h : user <=> kernel API between Linux raidtools and RAID drivers
          Copyright (C) 1998 Ingo Molnar

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   You should have received a copy of the GNU General Public License
   (for example /usr/src/linux/COPYING); if not, write to the Free
   Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef _MD_U_H
#define _MD_U_H

#include <linux/types.h>

#define MD_NAME_LEN                     32
#define MD_UUID_LEN                     16
#define MD_CTL_NODE                     "md-control"

/* ioctls */

/* status */
#define RAID_VERSION		_IOR (MD_MAJOR, 0x10, mdu_version_t)
#define GET_ARRAY_INFO		_IOR (MD_MAJOR, 0x11, mdu_array_info_t)
#define GET_DISK_INFO		_IOR (MD_MAJOR, 0x12, mdu_disk_info_t)
#define RAID_AUTORUN		_IO (MD_MAJOR, 0x14)
#define GET_BITMAP_FILE		_IOR (MD_MAJOR, 0x15, mdu_bitmap_file_t)

/* configuration */
#define ADD_NEW_DISK		_IOW (MD_MAJOR, 0x21, mdu_disk_info_t)
#define HOT_REMOVE_DISK		_IO (MD_MAJOR, 0x22)
#define SET_ARRAY_INFO		_IOW (MD_MAJOR, 0x23, mdu_array_info_t)
#define SET_DISK_FAULTY		_IO (MD_MAJOR, 0x29)
#define SET_BITMAP_FILE		_IOW (MD_MAJOR, 0x2b, int)

/* usage */
#define RUN_ARRAY		_IOW (MD_MAJOR, 0x30, mdu_param_t)
#define STOP_ARRAY		_IO (MD_MAJOR, 0x32)
#define STOP_ARRAY_RO		_IO (MD_MAJOR, 0x33)
#define RESTART_ARRAY_RW	_IO (MD_MAJOR, 0x34)
#define CLUSTERED_DISK_NACK	_IO (MD_MAJOR, 0x35)

/* ioctl commands for the MD misc control driver */
/* status */
#define MD_CTL_RAID_VERSION          _IOR(MD_MAJOR, 0x40, struct mdu_version64)
#define MD_CTL_LOOKUP_ARRAY          _IOWR(MD_MAJOR, 0x41, struct mdu_ioctl)
#define MD_CTL_GET_ARRAY_INFO	     _IOWR(MD_MAJOR, 0x42, struct mdu_ioctl)
#define MD_CTL_GET_DISK_INFO	     _IOWR(MD_MAJOR, 0x43, struct mdu_ioctl)
#define MD_CTL_GET_BITMAP_FILE	     _IOWR(MD_MAJOR, 0x44, struct mdu_ioctl)

/* configuration */
#define MD_CTL_SET_ARRAY_INFO        _IOWR(MD_MAJOR, 0x50, struct mdu_ioctl)
#define MD_CTL_ADD_NEW_DISK	     _IOWR(MD_MAJOR, 0x51, struct mdu_ioctl)
#define MD_CTL_HOT_ADD_DISK	     _IOWR(MD_MAJOR, 0x52, struct mdu_ioctl)
#define MD_CTL_HOT_REMOVE_DISK	     _IOWR(MD_MAJOR, 0x53, struct mdu_ioctl)
#define MD_CTL_SET_DISK_FAULTY	     _IOWR(MD_MAJOR, 0x54, struct mdu_ioctl)
#define MD_CTL_SET_BITMAP_FILE	     _IOWR(MD_MAJOR, 0x55, struct mdu_ioctl)

/* usage */
#define MD_CTL_RUN_ARRAY	     _IOWR(MD_MAJOR, 0x60, struct mdu_ioctl)
#define MD_CTL_STOP_ARRAY	     _IOWR(MD_MAJOR, 0x61, struct mdu_ioctl)
#define MD_CTL_RESTART_ARRAY_RW	     _IOWR(MD_MAJOR, 0x62, struct mdu_ioctl)
#define MD_CTL_CLUSTERED_DISK_NACK   _IOWR(MD_MAJOR, 0x63, struct mdu_ioctl)

typedef struct mdu_version_s {
	int major;
	int minor;
	int patchlevel;
} mdu_version_t;

typedef struct mdu_array_info_s {
	/*
	 * Generic constant information
	 */
	int major_version;
	int minor_version;
	int patch_version;
	unsigned int ctime;
	int level;
	int size;
	int nr_disks;
	int raid_disks;
	int md_minor;
	int not_persistent;

	/*
	 * Generic state information
	 */
	unsigned int utime;	/*  0 Superblock update time		      */
	int state;		/*  1 State bits (clean, ...)		      */
	int active_disks;	/*  2 Number of currently active disks	      */
	int working_disks;	/*  3 Number of working disks		      */
	int failed_disks;	/*  4 Number of failed disks		      */
	int spare_disks;	/*  5 Number of spare disks		      */

	/*
	 * Personality information
	 */
	int layout;		/*  0 the array's physical layout	      */
	int chunk_size;	/*  1 chunk size in bytes		      */

} mdu_array_info_t;

typedef struct mdu_disk_info_s {
	/*
	 * configuration/status of one particular disk
	 */
	int number;
	int major;
	int minor;
	int raid_disk;
	int state;

} mdu_disk_info_t;

typedef struct mdu_start_info_s {
	/*
	 * configuration/status of one particular disk
	 */
	int major;
	int minor;
	int raid_disk;
	int state;

} mdu_start_info_t;

typedef struct mdu_bitmap_file_s
{
	char pathname[4096];
} mdu_bitmap_file_t;

typedef struct mdu_param_s
{
	int			personality;	/* 1,2,3,4 */
	int			chunk_size;	/* in bytes */
	int			max_fault;	/* unused for now */
} mdu_param_t;

/* structures for the MD misc control driver */
struct mdu_version64 {
	__u32 major;
	__u32 minor;
	__u32 patchlevel;
	__u32 padding;
};

struct mdu_array_info64 {
	/*
	 * Generic constant information
	 */
	__u32 major_version;
	__u32 minor_version;
	__u32 patch_version;
	__s32 level;

	__u64 ctime;
	__s64 size;

	__u32 nr_disks;
	__u32 raid_disks;
	__u32 md_minor;
	__u32 not_persistent;

	/*
	 * Generic state information
	 */
	__u64 utime;		/*  0 Superblock update time		      */

	__u32 state;		/*  1 State bits (clean, ...)		      */
	__u32 active_disks;	/*  2 Number of currently active disks	      */
	__u32 working_disks;	/*  3 Number of working disks		      */
	__u32 failed_disks;	/*  4 Number of failed disks		      */
	__u32 spare_disks;	/*  5 Number of spare disks		      */
	__u32 journal_disks;    /*  6 Number of disks used for journaling     */

	/*
	 * Personality information
	 */
	__s32 layout;		/*  0 the array's physical layout	      */
	__u32 chunk_size;	/*  1 chunk size in bytes		      */

};

struct mdu_disk_info64 {
	/*
	 * configuration/status of one particular disk
	 */
	__u32 state;
	__u32 major;
	__u32 minor;
	__u32 padding;

	__s32 number;
	__s32 raid_disk;
};

struct mdu_param64 {
	__s32 personality;	/* 1,2,3,4 */
	__u32 max_fault;	/* unused for now */
	__u32 chunk_size;	/* in bytes */
	__u32 padding;
};

struct mdu_ioctl {
	char md_name[MD_NAME_LEN];
	char md_uuid[MD_UUID_LEN];
	__u64 md_dev;               /* md array device number              */
	__u32 flags;                /* Flags for the ioctl operation       */
	__u32 padding;
	union {
		__u64 array;        /* Pointer to struct mdu_array_info64  */
		__u64 disk;         /* Pointer to struct mdu_disk_info64   */
		__u64 param;        /* Pointer to struct mdu_param64       */

		/* GET_BITMAP_FILE: pointer to struct mdu_bitmap_file_s
		 * SET_BITMAP_FILE: file descriptor.
		 */
		__u64 bitmap_file;
		__u64 disk_dev;     /* Disk device number                  */
		__u64 arg;          /* Generic argument                    */
	};
};

/*
 * If set, MD_STOP_ARRAY will switch the array to read-only mode instead
 * of fully stopping it.
 */
#define MD_CTL_RO_FLAG              (1u << 0)

#endif
