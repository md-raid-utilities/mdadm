/*
 * mdadm - manage Linux "md" devices aka RAID arrays.
 *
 * Copyright (C) 2011  Neil Brown <neilb@suse.de>
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
#include	"dlink.h"
#include	"xmalloc.h"

#include	<ctype.h>
#include	<limits.h>

/* Fixed-width signed type is used because short size is not guaranteed to be 16 bits. */
int16_t le16_to_cpu_s(__le16 value)
{
	return (int16_t)__le16_to_cpu(value);
}

/* Fixed-width signed type is used because int size is not guaranteed to be 32 bits. */
int32_t le32_to_cpu_s(__le32 value)
{
	return (int32_t)__le32_to_cpu(value);
}

/**
 * is_string_lq() - Check if string length with NULL byte is lower or equal to requested.
 * @str: string to check.
 * @max_len: max length.
 *
 * @str length must be bigger than 0 and be lower or equal @max_len, including termination byte.
 */
bool is_string_lq(const char * const str, size_t max_len)
{
	assert(str);

	size_t _len = strnlen(str, max_len);

	if (_len > 0 && _len < max_len)
		return true;
	return false;
}

bool is_dev_alive(char *path)
{
	if (!path)
		return false;

	if (access(path, R_OK) == 0)
		return true;

	return false;
}

/* This fill contains various 'library' style function.  They
 * have no dependency on anything outside this file.
 */

int get_mdp_major(void)
{
	static int mdp_major = -1;
	bool in_block_devices = false;
	char line[128];
	FILE *fl;

	if (mdp_major != -1)
		return mdp_major;

	fl = fopen("/proc/devices", "r");
	if (!fl)
		return -1;

	while (fgets(line, sizeof(line), fl)) {
		char name[MD_NAME_MAX];
		int device_major;

		if (strcmp(line, "Block devices:\n") == 0) {
			in_block_devices = true;
			continue;
		}

		if (in_block_devices &&
		    sscanf(line, "%d %31s", &device_major, name) == 2 &&
		    strcmp(name, "mdp") == 0) {
			mdp_major = device_major;
			break;
		}
	}
	fclose(fl);

	return mdp_major;
}

/**
 * devid2kname() - Get kernel device name for a device ID.
 * @devid: Device ID to resolve.
 *
 * Return the last component of the /sys/dev/block/MAJOR:MINOR link.
 */
char *devid2kname(dev_t devid)
{
	static char devnm[32];
	char link[PATH_MAX];
	char path[64];
	ssize_t len;
	char *name;

	if (snprintf(path, sizeof(path), "/sys/dev/block/%d:%d",
		     major(devid), minor(devid)) >= (int)sizeof(path))
		return NULL;

	len = readlink(path, link, sizeof(link) - 1);
	if (len <= 0 || len == (ssize_t)sizeof(link) - 1)
		return NULL;
	link[len] = '\0';

	name = strrchr(link, '/');
	if (!name || !name[1])
		return NULL;

	snprintf(devnm, sizeof(devnm), "%s", name + 1);
	return devnm;
}

char *stat2kname(struct stat *st)
{
	if ((S_IFMT & st->st_mode) != S_IFBLK)
		return NULL;

	return devid2kname(st->st_rdev);
}

char *fd2kname(int fd)
{
	struct stat stb;

	if (fstat(fd, &stb) == 0)
		return stat2kname(&stb);

	return NULL;
}

/**
 * devid2devnm() - Get the kernel MD device name for a device ID.
 * @devid: Device ID to resolve.
 *
 * Resolve partitions to their parent MD device. Fall back to deriving the
 * name from the device number when sysfs is unavailable.
 */
char *devid2devnm(dev_t devid)
{
	static char devnm[32];
	char link[PATH_MAX];
	char path[64];
	char *name;
	char *end;
	ssize_t len;
	int ret;

	ret = snprintf(path, sizeof(path), "/sys/dev/block/%d:%d",
		       major(devid), minor(devid));
	if (ret < 0 || ret >= (int)sizeof(path))
		goto fallback;

	len = readlink(path, link, sizeof(link) - 1);
	if (len <= 0 || len == (ssize_t)sizeof(link) - 1)
		goto fallback;
	link[len] = '\0';

	name = strstr(link, "/block/");
	if (!name)
		goto fallback;
	name += sizeof("/block/") - 1;

	end = strchr(name, '/');
	if (end)
		*end = '\0';
	if (!name[0])
		goto fallback;

	snprintf(devnm, sizeof(devnm), "%s", name);
	return devnm;

fallback:
	if (major(devid) == MD_MAJOR)
		snprintf(devnm, sizeof(devnm), "md%d", minor(devid));
	else if (major(devid) == (unsigned)get_mdp_major())
		snprintf(devnm, sizeof(devnm), "md_d%d",
			 minor(devid) >> MdpMinorShift);
	else
		return NULL;

	return devnm;
}

char *stat2devnm(struct stat *st)
{
	if ((S_IFMT & st->st_mode) != S_IFBLK)
		return NULL;

	return devid2devnm(st->st_rdev);
}

bool stat_is_md_dev(struct stat *st)
{
	if ((S_IFMT & st->st_mode) != S_IFBLK)
		return false;
	if (major(st->st_rdev) == MD_MAJOR)
		return true;
	if (major(st->st_rdev) == (unsigned)get_mdp_major())
		return true;

	return false;
}

char *fd2devnm(int fd)
{
	struct stat stb;

	if (fstat(fd, &stb) == 0)
		return stat2devnm(&stb);

	return NULL;
}

/*
 * convert a major/minor pair for a block device into a name in /dev, if possible.
 * On the first call, walk /dev collecting name.
 * Put them in a simple linked listfor now.
 */
struct devmap {
	int major, minor;
	char *name;
	struct devmap *next;
} *devlist = NULL;
int devlist_ready = 0;

int add_dev(const char *name, const struct stat *stb, int flag, struct FTW *s)
{
	struct stat st;

	if (S_ISLNK(stb->st_mode)) {
		if (stat(name, &st) != 0)
			return 0;
		stb = &st;
	}

	if ((stb->st_mode&S_IFMT)== S_IFBLK) {
		char *n = xstrdup(name);
		struct devmap *dm = xmalloc(sizeof(*dm));
		if (strncmp(n, "/dev/./", 7) == 0)
			strcpy(n + 4, name + 6);
		if (dm) {
			dm->major = major(stb->st_rdev);
			dm->minor = minor(stb->st_rdev);
			dm->name = n;
			dm->next = devlist;
			devlist = dm;
		}
	}

	return 0;
}

/*
 * Find a block device with the right major/minor number.
 * If we find multiple names, choose the shortest.
 * If we find a name in /dev/md/, we prefer that.
 * This applies only to names for MD devices.
 * If 'prefer' is set (normally to e.g. /by-path/)
 * then we prefer a name which contains that string.
 */
char *map_dev_preferred(int major, int minor, int create,
			char *prefer)
{
	struct devmap *p;
	char *regular = NULL, *preferred=NULL;
	int did_check = 0;

	if (major == 0 && minor == 0)
		return NULL;

 retry:
	if (!devlist_ready) {
		char *dev = "/dev";
		struct stat stb;
		while(devlist) {
			struct devmap *d = devlist;
			devlist = d->next;
			free(d->name);
			free(d);
		}
		if (lstat(dev, &stb) == 0 && S_ISLNK(stb.st_mode))
			dev = "/dev/.";
		nftw(dev, add_dev, 10, FTW_PHYS);
		devlist_ready=1;
		did_check = 1;
	}

	for (p = devlist; p; p = p->next)
		if (p->major == major && p->minor == minor) {
			if (strncmp(p->name, DEV_MD_DIR, DEV_MD_DIR_LEN) == 0 ||
			    (prefer && strstr(p->name, prefer))) {
				if (preferred == NULL ||
				    strlen(p->name) < strlen(preferred))
					preferred = p->name;
			} else {
				if (regular == NULL ||
				    strlen(p->name) < strlen(regular))
					regular = p->name;
			}
		}
	if (!regular && !preferred && !did_check) {
		devlist_ready = 0;
		goto retry;
	}
	if (create && !regular && !preferred) {
		static char buf[30];
		snprintf(buf, sizeof(buf), "%d:%d", major, minor);
		regular = buf;
	}

	return preferred ? preferred : regular;
}

void print_quoted(char *str)
{
	/* Printf the string with surrounding quotes
	 * iff needed.
	 * If no space, tab, or quote - leave unchanged.
	 * Else print surrounded by " or ', swapping quotes
	 * when we find one that will cause confusion.
	 */

	char first_quote = 0, q;
	char *c;

	for (c = str; *c; c++) {
		switch(*c) {
		case '\'':
		case '"':
			first_quote = *c;
			break;
		case ' ':
		case '\t':
			first_quote = *c;
			continue;
		default:
			continue;
		}
		break;
	}
	if (!first_quote) {
		printf("%s", str);
		return;
	}

	if (first_quote == '"')
		q = '\'';
	else
		q = '"';
	putchar(q);
	for (c = str; *c; c++) {
		if (*c == q) {
			putchar(q);
			q ^= '"' ^ '\'';
			putchar(q);
		}
		putchar(*c);
	}
	putchar(q);
}

/**
 * is_alphanum() - Check if sign is letter or digit.
 * @c: char to analyze.
 *
 * Similar to isalnum() but additional locales are excluded.
 *
 * Return: %true on success, %false otherwise.
 */
bool is_alphanum(const char c)
{
	if (isupper(c) || islower(c) || isdigit(c) != 0)
		return true;
	return false;
}

/**
 * is_name_posix_compatible() - Check if name is POSIX compatible.
 * @name: name to check.
 *
 *  POSIX portable file name character set contains ASCII letters,
 *  digits, '_', '.', and '-'. Also forbid leading '-'.
 *  The length of the name cannot exceed NAME_MAX - 1 (ensure NULL ending).
 *
 * Return: %true on success, %false otherwise.
 */
bool is_name_posix_compatible(const char * const name)
{
	assert(name);

	char allowed_symbols[] = "-_.";
	const char *n = name;

	if (!is_string_lq(name, NAME_MAX))
		return false;

	if (*n == '-')
		return false;

	while (*n != '\0') {
		if (!is_alphanum(*n) && !strchr(allowed_symbols, *n))
			return false;
		n++;
	}
	return true;
}

int check_env(char *name)
{
	char *val = getenv(name);

	if (val && atoi(val) == 1)
		return 1;

	return 0;
}

unsigned long GCD(unsigned long a, unsigned long b)
{
	while (a != b) {
		if (a < b)
			b -= a;
		if (b < a)
			a -= b;
	}
	return a;
}

/**
 * parse_num() - Parse int from string.
 * @dest: Pointer to destination.
 * @num: Pointer to string that is going to be parsed.
 *
 * If string contains anything after a number, error code is returned.
 * The same happens when number is bigger than INT_MAX or smaller than 0.
 * Writes to destination only if successfully read the number.
 *
 * Return: 0 on success, 1 otherwise.
 */
int parse_num(int *dest, const char *num)
{
	char *c = NULL;
	long temp;

	if (!num)
		return 1;

	errno = 0;
	temp = strtol(num, &c, 10);
	if (temp < 0 || temp > INT_MAX || *c || errno != 0 || num == c)
		return 1;
	*dest = temp;
	return 0;
}

/**
 * s_gethostname() - secure get hostname. Assure null-terminated string.
 *
 * @buf: buffer for hostname.
 * @buf_len: buffer length.
 *
 * Return: gethostname() result.
 */
int s_gethostname(char *buf, int buf_len)
{
	assert(buf);

	int ret = gethostname(buf, buf_len);

	buf[buf_len - 1] = 0;

	return ret;
}
