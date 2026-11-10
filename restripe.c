/*
 * mdadm - manage Linux "md" devices aka RAID arrays.
 *
 * Copyright (C) 2006-2009 Neil Brown <neilb@suse.de>
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

#include "mdadm.h"
#include "xmalloc.h"

#include <stdint.h>

/* To restripe, we read from old geometry to a buffer, and
 * read from buffer to new geometry.
 * When reading, we might have missing devices and so could need
 * to reconstruct.
 * When writing, we need to create correct parity and Q.
 *
 */

int geo_map(int block, unsigned long long stripe, int raid_disks,
		   int level, int layout)
{
	/* On the given stripe, find which disk in the array will have
	 * block numbered 'block'.
	 * '-1' means the parity block.
	 * '-2' means the Q syndrome.
	 */
	int pd;

	/* layout is not relevant for raid0 and raid4 */
	if ((level == 0) ||
	    (level == 4))
		layout = 0;

	switch(level*100 + layout) {
	case 000:
	case 400:
	case 500 + ALGORITHM_PARITY_N:
		/* raid 4 isn't messed around by parity blocks */
		if (block == -1)
			return raid_disks-1; /* parity block */
		return block;
	case 500 + ALGORITHM_LEFT_ASYMMETRIC:
		pd = (raid_disks-1) - stripe % raid_disks;
		if (block == -1)
			return pd;
		if (block >= pd)
			block++;
		return block;

	case 500 + ALGORITHM_RIGHT_ASYMMETRIC:
		pd = stripe % raid_disks;
		if (block == -1)
			return pd;
		if (block >= pd)
			block++;
		return block;

	case 500 + ALGORITHM_LEFT_SYMMETRIC:
		pd = (raid_disks - 1) - stripe % raid_disks;
		if (block == -1)
			return pd;
		return (pd + 1 + block) % raid_disks;

	case 500 + ALGORITHM_RIGHT_SYMMETRIC:
		pd = stripe % raid_disks;
		if (block == -1)
			return pd;
		return (pd + 1 + block) % raid_disks;

	case 500 + ALGORITHM_PARITY_0:
		return block + 1;

	case 600 + ALGORITHM_PARITY_N_6:
		if (block == -2)
			return raid_disks - 1;
		if (block == -1)
			return raid_disks - 2; /* parity block */
		return block;
	case 600 + ALGORITHM_LEFT_ASYMMETRIC_6:
		if (block == -2)
			return raid_disks - 1;
		raid_disks--;
		pd = (raid_disks-1) - stripe % raid_disks;
		if (block == -1)
			return pd;
		if (block >= pd)
			block++;
		return block;

	case 600 + ALGORITHM_RIGHT_ASYMMETRIC_6:
		if (block == -2)
			return raid_disks - 1;
		raid_disks--;
		pd = stripe % raid_disks;
		if (block == -1)
			return pd;
		if (block >= pd)
			block++;
		return block;

	case 600 + ALGORITHM_LEFT_SYMMETRIC_6:
		if (block == -2)
			return raid_disks - 1;
		raid_disks--;
		pd = (raid_disks - 1) - stripe % raid_disks;
		if (block == -1)
			return pd;
		return (pd + 1 + block) % raid_disks;

	case 600 + ALGORITHM_RIGHT_SYMMETRIC_6:
		if (block == -2)
			return raid_disks - 1;
		raid_disks--;
		pd = stripe % raid_disks;
		if (block == -1)
			return pd;
		return (pd + 1 + block) % raid_disks;

	case 600 + ALGORITHM_PARITY_0_6:
		if (block == -2)
			return raid_disks - 1;
		return block + 1;

	case 600 + ALGORITHM_PARITY_0:
		if (block == -1)
			return 0;
		if (block == -2)
			return 1;
		return block + 2;

	case 600 + ALGORITHM_LEFT_ASYMMETRIC:
		pd = raid_disks - 1 - (stripe % raid_disks);
		if (block == -1)
			return pd;
		if (block == -2)
			return (pd+1) % raid_disks;
		if (pd == raid_disks - 1)
			return block+1;
		if (block >= pd)
			return block+2;
		return block;

	case 600 + ALGORITHM_ROTATING_ZERO_RESTART:
		/* Different order for calculating Q, otherwize same as ... */
	case 600 + ALGORITHM_RIGHT_ASYMMETRIC:
		pd = stripe % raid_disks;
		if (block == -1)
			return pd;
		if (block == -2)
			return (pd+1) % raid_disks;
		if (pd == raid_disks - 1)
			return block+1;
		if (block >= pd)
			return block+2;
		return block;

	case 600 + ALGORITHM_LEFT_SYMMETRIC:
		pd = raid_disks - 1 - (stripe % raid_disks);
		if (block == -1)
			return pd;
		if (block == -2)
			return (pd+1) % raid_disks;
		return (pd + 2 + block) % raid_disks;

	case 600 + ALGORITHM_RIGHT_SYMMETRIC:
		pd = stripe % raid_disks;
		if (block == -1)
			return pd;
		if (block == -2)
			return (pd+1) % raid_disks;
		return (pd + 2 + block) % raid_disks;

	case 600 + ALGORITHM_ROTATING_N_RESTART:
		/* Same a left_asymmetric, by first stripe is
		 * D D D P Q  rather than
		 * Q D D D P
		 */
		pd = raid_disks - 1 - ((stripe + 1) % raid_disks);
		if (block == -1)
			return pd;
		if (block == -2)
			return (pd+1) % raid_disks;
		if (pd == raid_disks - 1)
			return block+1;
		if (block >= pd)
			return block+2;
		return block;

	case 600 + ALGORITHM_ROTATING_N_CONTINUE:
		/* Same as left_symmetric but Q is before P */
		pd = raid_disks - 1 - (stripe % raid_disks);
		if (block == -1)
			return pd;
		if (block == -2)
			return (pd+raid_disks-1) % raid_disks;
		return (pd + 1 + block) % raid_disks;
	}
	return -1;
}

int is_ddf(int layout)
{
	switch (layout)
	{
	default:
		return 0;
	case ALGORITHM_ROTATING_N_CONTINUE:
	case ALGORITHM_ROTATING_N_RESTART:
	case ALGORITHM_ROTATING_ZERO_RESTART:
		return 1;
	}
}

void xor_blocks(char *target, char **sources, int disks, int size)
{
	int i, j;
	/* Amazingly inefficient... */
	for (i=0; i<size; i++) {
		char c = 0;
		for (j=0 ; j<disks; j++)
			c ^= sources[j][i];
		target[i] = c;
	}
}

void qsyndrome(uint8_t *p, uint8_t *q, uint8_t **sources, int disks, int size)
{
	int d, z;
	uint8_t wq0, wp0, wd0, w10, w20;
	for ( d = 0; d < size; d++) {
		wq0 = wp0 = sources[disks-1][d];
		for ( z = disks-2 ; z >= 0 ; z-- ) {
			wd0 = sources[z][d];
			wp0 ^= wd0;
			w20 = (wq0&0x80) ? 0xff : 0x00;
			w10 = (wq0 << 1) & 0xff;
			w20 &= 0x1d;
			w10 ^= w20;
			wq0 = w10 ^ wd0;
		}
		p[d] = wp0;
		q[d] = wq0;
	}
}

/*
 * The following was taken from linux/drivers/md/mktables.c, and modified
 * to create in-memory tables rather than C code
 */
static uint8_t gfmul(uint8_t a, uint8_t b)
{
	uint8_t v = 0;

	while (b) {
		if (b & 1)
			v ^= a;
		a = (a << 1) ^ (a & 0x80 ? 0x1d : 0);
		b >>= 1;
	}

	return v;
}

static uint8_t gfpow(uint8_t a, int b)
{
	uint8_t v = 1;

	b %= 255;
	if (b < 0)
		b += 255;

	while (b) {
		if (b & 1)
			v = gfmul(v, a);
		a = gfmul(a, a);
		b >>= 1;
	}

	return v;
}

int tables_ready = 0;
uint8_t raid6_gfmul[256][256];
uint8_t raid6_gfexp[256];
uint8_t raid6_gfinv[256];
uint8_t raid6_gfexi[256];
uint8_t raid6_gflog[256];
void make_tables(void)
{
	int i, j;
	uint8_t v;
	uint32_t b, log;

	/* Compute multiplication table */
	for (i = 0; i < 256; i++)
		for (j = 0; j < 256; j++)
				raid6_gfmul[i][j] = gfmul(i, j);

	/* Compute power-of-2 table (exponent) */
	v = 1;
	for (i = 0; i < 256; i++) {
		raid6_gfexp[i] = v;
		v = gfmul(v, 2);
		if (v == 1)
			v = 0;	/* For entry 255, not a real entry */
	}

	/* Compute inverse table x^-1 == x^254 */
	for (i = 0; i < 256; i++)
		raid6_gfinv[i] = gfpow(i, 254);

	/* Compute inv(2^x + 1) (exponent-xor-inverse) table */
	for (i = 0; i < 256; i ++)
		raid6_gfexi[i] = raid6_gfinv[raid6_gfexp[i] ^ 1];

	/* Compute log */
	/* Modified code from:
	 *    https://web.eecs.utk.edu/~plank/plank/papers/CS-96-332.html
	 */
	b = 1;
	raid6_gflog[0] = 0;
	for (log = 0; log < 255; log++) {
		raid6_gflog[b] = (uint8_t) log;
		b = b << 1;
		if (b & 256) b = b ^ 0435;
	}

	tables_ready = 1;
}

uint8_t *zero;
int zero_size;

void ensure_zero_has_size(int chunk_size)
{
	if (zero == NULL || chunk_size > zero_size) {
		if (zero)
			free(zero);
		zero = xcalloc(1, chunk_size);
		zero_size = chunk_size;
	}
}

/* Following was taken from linux/drivers/md/raid6recov.c */

/* Recover two failed data blocks. */

void raid6_2data_recov(int disks, size_t bytes, int faila, int failb,
		       uint8_t **ptrs, int neg_offset)
{
	uint8_t *p, *q, *dp, *dq;
	uint8_t px, qx, db;
	const uint8_t *pbmul;	/* P multiplier table for B data */
	const uint8_t *qmul;		/* Q multiplier table (for both) */

	if (faila > failb) {
		int t = faila;
		faila = failb;
		failb = t;
	}

	if (neg_offset) {
		p = ptrs[-1];
		q = ptrs[-2];
	} else {
		p = ptrs[disks-2];
		q = ptrs[disks-1];
	}

	/* Compute syndrome with zero for the missing data pages
	   Use the dead data pages as temporary storage for
	   delta p and delta q */
	dp = ptrs[faila];
	ptrs[faila] = zero;
	dq = ptrs[failb];
	ptrs[failb] = zero;

	qsyndrome(dp, dq, ptrs, disks-2, bytes);

	/* Restore pointer table */
	ptrs[faila]   = dp;
	ptrs[failb]   = dq;

	/* Now, pick the proper data tables */
	pbmul = raid6_gfmul[raid6_gfexi[failb-faila]];
	qmul  = raid6_gfmul[raid6_gfinv[raid6_gfexp[faila]^raid6_gfexp[failb]]];

	/* Now do it... */
	while ( bytes-- ) {
		px    = *p ^ *dp;
		qx    = qmul[*q ^ *dq];
		*dq++ = db = pbmul[px] ^ qx; /* Reconstructed B */
		*dp++ = db ^ px; /* Reconstructed A */
		p++; q++;
	}
}

/* Recover failure of one data block plus the P block */
void raid6_datap_recov(int disks, size_t bytes, int faila, uint8_t **ptrs,
		       int neg_offset)
{
	uint8_t *p, *q, *dq;
	const uint8_t *qmul;		/* Q multiplier table */

	if (neg_offset) {
		p = ptrs[-1];
		q = ptrs[-2];
	} else {
		p = ptrs[disks-2];
		q = ptrs[disks-1];
	}

	/* Compute syndrome with zero for the missing data page
	   Use the dead data page as temporary storage for delta q */
	dq = ptrs[faila];
	ptrs[faila] = zero;

	qsyndrome(p, dq, ptrs, disks-2, bytes);

	/* Restore pointer table */
	ptrs[faila]   = dq;

	/* Now, pick the proper data tables */
	qmul  = raid6_gfmul[raid6_gfinv[raid6_gfexp[faila]]];

	/* Now do it... */
	while ( bytes-- ) {
		*p++ ^= *dq = qmul[*q ^ *dq];
		q++; dq++;
	}
}

/*******************************************************************************
 * Function:	save_stripes
 * Description:
 *	Function reads data (only data without P and Q) from array and writes
 * it to buf and opcjonaly to backup files
 * Parameters:
 *	source		: A list of 'fds' of the active disks.
 *			  Some may be absent
 *	offsets		: A list of offsets on disk belonging
 *			 to the array [bytes]
 *	raid_disks	: geometry: number of disks in the array
 *	chunk_size	: geometry: chunk size [bytes]
 *	level		: geometry: RAID level
 *	layout		: geometry: layout
 *	nwrites		: number of backup files
 *	dest		: A list of 'fds' for mirrored targets
 *			  (e.g. backup files). They are already seeked to right
 *			  (write) location. If NULL, data will be wrote
 *			  to the buf only
 *	start		: start address of data to read (must be stripe-aligned)
 *			  [bytes]
 *	length	-	: length of data to read (must be stripe-aligned)
 *			  [bytes]
 *	buf		: buffer for data. It is large enough to hold
 *			  one stripe. It is stripe aligned
 * Returns:
 *	 0 : success
 *	-1 : fail
 ******************************************************************************/
int save_stripes(int *source, unsigned long long *offsets,
		 int raid_disks, int chunk_size, int level, int layout,
		 int nwrites, int *dest,
		 unsigned long long start, unsigned long long length,
		 char *buf)
{
	int len;
	int data_disks = raid_disks - (level == 0 ? 0 : level <=5 ? 1 : 2);
	int disk;
	int i;
	unsigned long long length_test;

	if (!tables_ready)
		make_tables();
	ensure_zero_has_size(chunk_size);

	len = data_disks * chunk_size;
	length_test = length / len;
	length_test *= len;

	if (length != length_test) {
		dprintf("Error: save_stripes(): Data are not alligned. EXIT\n");
		dprintf("\tArea for saving stripes (length) = %llu\n", length);
		dprintf("\tWork step (len)                  = %i\n", len);
		dprintf("\tExpected save area (length_test) = %llu\n",
			length_test);
		abort();
	}

	while (length > 0) {
		int failed = 0;
		int fdisk[3], fblock[3];
		for (disk = 0; disk < raid_disks ; disk++) {
			unsigned long long offset;
			int dnum;

			offset = (start/chunk_size/data_disks)*chunk_size;
			dnum = geo_map(disk < data_disks ? disk : data_disks - disk - 1,
				       start/chunk_size/data_disks,
				       raid_disks, level, layout);
			if (dnum < 0) abort();
			if (source[dnum] < 0 ||
			    lseek(source[dnum], offsets[dnum] + offset, 0) < 0 ||
			    read(source[dnum], buf+disk * chunk_size,
				 chunk_size) != chunk_size) {
				if (failed <= 2) {
					fdisk[failed] = dnum;
					fblock[failed] = disk;
					failed++;
				}
			}
		}
		if (failed == 0 || fblock[0] >= data_disks)
			/* all data disks are good */
			;
		else if (failed == 1 || fblock[1] >= data_disks+1) {
			/* one failed data disk and good parity */
			char *bufs[data_disks];
			for (i=0; i < data_disks; i++)
				if (fblock[0] == i)
					bufs[i] = buf + data_disks*chunk_size;
				else
					bufs[i] = buf + i*chunk_size;

			xor_blocks(buf + fblock[0]*chunk_size,
				   bufs, data_disks, chunk_size);
		} else if (failed > 2 || level != 6)
			/* too much failure */
			return -1;
		else {
			/* RAID6 computations needed. */
			uint8_t *bufs[data_disks+4];
			int qdisk;
			int syndrome_disks;
			disk = geo_map(-1, start/chunk_size/data_disks,
				       raid_disks, level, layout);
			qdisk = geo_map(-2, start/chunk_size/data_disks,
				       raid_disks, level, layout);
			if (is_ddf(layout)) {
				/* q over 'raid_disks' blocks, in device order.
				 * 'p' and 'q' get to be all zero
				 */
				for (i = 0; i < raid_disks; i++)
					bufs[i] = zero;
				for (i = 0; i < data_disks; i++) {
					int dnum = geo_map(i,
							   start/chunk_size/data_disks,
							   raid_disks, level, layout);
					int snum;
					/* i is the logical block number, so is index to 'buf'.
					 * dnum is physical disk number
					 * and thus the syndrome number.
					 */
					snum = dnum;
					bufs[snum] = (uint8_t*)buf + chunk_size * i;
				}
				syndrome_disks = raid_disks;
			} else {
				/* for md, q is over 'data_disks' blocks,
				 * starting immediately after 'q'
				 * Note that for the '_6' variety, the p block
				 * makes a hole that we need to be careful of.
				 */
				int j;
				int snum = 0;
				for (j = 0; j < raid_disks; j++) {
					int dnum = (qdisk + 1 + j) % raid_disks;
					if (dnum == disk || dnum == qdisk)
						continue;
					for (i = 0; i < data_disks; i++)
						if (geo_map(i,
							    start/chunk_size/data_disks,
							    raid_disks, level, layout) == dnum)
							break;
					/* i is the logical block number, so is index to 'buf'.
					 * dnum is physical disk number
					 * snum is syndrome disk for which 0 is immediately after Q
					 */
					bufs[snum] = (uint8_t*)buf + chunk_size * i;

					if (fblock[0] == i)
						fdisk[0] = snum;
					if (fblock[1] == i)
						fdisk[1] = snum;
					snum++;
				}

				syndrome_disks = data_disks;
			}

			/* Place P and Q blocks at end of bufs */
			bufs[syndrome_disks] = (uint8_t*)buf + chunk_size * data_disks;
			bufs[syndrome_disks+1] = (uint8_t*)buf + chunk_size * (data_disks+1);

			if (fblock[1] == data_disks)
				/* One data failed, and parity failed */
				raid6_datap_recov(syndrome_disks+2, chunk_size,
						  fdisk[0], bufs, 0);
			else {
				/* Two data blocks failed, P,Q OK */
				raid6_2data_recov(syndrome_disks+2, chunk_size,
						  fdisk[0], fdisk[1], bufs, 0);
			}
		}
		if (dest) {
			for (i = 0; i < nwrites; i++)
				if (write(dest[i], buf, len) != len)
					return -1;
		} else {
			/* build next stripe in buffer */
			buf += len;
		}
		length -= len;
		start += len;
	}
	return 0;
}

/* Restore data:
 * We are given:
 *  A list of 'fds' of the active disks. Some may be '-1' for not-available.
 *  A geometry: raid_disks, chunk_size, level, layout
 *  An 'fd' to read from.  It is already seeked to the right (Read) location.
 *  A start and length.
 * The length must be a multiple of the stripe size.
 *
 * We build a full stripe in memory and then write it out.
 * We assume that there are enough working devices.
 */
int restore_stripes(int *dest, unsigned long long *offsets,
		    int raid_disks, int chunk_size, int level, int layout,
		    int source, unsigned long long read_offset,
		    unsigned long long start, unsigned long long length,
		    char *src_buf)
{
	char *stripe_buf;
	char **stripes = xmalloc(raid_disks * sizeof(char*));
	char **blocks = xmalloc(raid_disks * sizeof(char*));
	int i;
	int rv;

	int data_disks = raid_disks - (level == 0 ? 0 : level <= 5 ? 1 : 2);

	if (posix_memalign((void**)&stripe_buf, 4096, raid_disks * chunk_size))
		stripe_buf = NULL;

	if (zero == NULL || chunk_size > zero_size) {
		if (zero)
			free(zero);
		zero = xcalloc(1, chunk_size);
		zero_size = chunk_size;
	}

	if (stripe_buf == NULL || stripes == NULL || blocks == NULL ||
	    zero == NULL) {
		rv = -2;
		goto abort;
	}
	for (i = 0; i < raid_disks; i++)
		stripes[i] = stripe_buf + i * chunk_size;
	while (length > 0) {
		unsigned int len = data_disks * chunk_size;
		unsigned long long offset;
		int disk, qdisk;
		int syndrome_disks;
		if (length < len) {
			rv = -3;
			goto abort;
		}
		for (i = 0; i < data_disks; i++) {
			int disk = geo_map(i, start/chunk_size/data_disks,
					   raid_disks, level, layout);
			if (src_buf == NULL) {
				/* read from file */
				if (lseek(source, read_offset, 0) !=
					 (off_t)read_offset) {
					rv = -1;
					goto abort;
				}
				if (read(source,
					 stripes[disk],
					 chunk_size) != chunk_size) {
					rv = -1;
					goto abort;
				}
			} else {
				/* read from input buffer */
				memcpy(stripes[disk],
				       src_buf + read_offset,
				       chunk_size);
			}
			read_offset += chunk_size;
		}
		/* We have the data, now do the parity */
		offset = (start/chunk_size/data_disks) * chunk_size;
		switch (level) {
		case 4:
		case 5:
			disk = geo_map(-1, start/chunk_size/data_disks,
					   raid_disks, level, layout);
			for (i = 0; i < data_disks; i++)
				blocks[i] = stripes[(disk+1+i) % raid_disks];
			xor_blocks(stripes[disk], blocks, data_disks, chunk_size);
			break;
		case 6:
			disk = geo_map(-1, start/chunk_size/data_disks,
				       raid_disks, level, layout);
			qdisk = geo_map(-2, start/chunk_size/data_disks,
				       raid_disks, level, layout);
			if (is_ddf(layout)) {
				/* q over 'raid_disks' blocks, in device order.
				 * 'p' and 'q' get to be all zero
				 */
				for (i = 0; i < raid_disks; i++)
					if (i == disk || i == qdisk)
						blocks[i] = (char*)zero;
					else
						blocks[i] = stripes[i];
				syndrome_disks = raid_disks;
			} else {
				/* for md, q is over 'data_disks' blocks,
				 * starting immediately after 'q'
				 */
				for (i = 0; i < data_disks; i++)
					blocks[i] = stripes[(qdisk+1+i) % raid_disks];

				syndrome_disks = data_disks;
			}
			qsyndrome((uint8_t*)stripes[disk],
				  (uint8_t*)stripes[qdisk],
				  (uint8_t**)blocks,
				  syndrome_disks, chunk_size);
			break;
		}
		for (i=0; i < raid_disks ; i++)
			if (dest[i] >= 0) {
				if (lseek(dest[i], offsets[i]+offset, 0) < 0) {
					rv = -1;
					goto abort;
				}
				if (write(dest[i], stripes[i],
					 chunk_size) != chunk_size) {
					rv = -1;
					goto abort;
				}
			}
		length -= len;
		start += len;
	}
	rv = 0;

abort:
	free(stripe_buf);
	free(stripes);
	free(blocks);
	return rv;
}
