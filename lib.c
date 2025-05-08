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
	FILE *fl;
	char *w;
	int have_block = 0;
	int have_devices = 0;
	int last_num = -1;

	if (mdp_major != -1)
		return mdp_major;

	fl = fopen("/proc/devices", "r");
	if (!fl)
		return -1;

	while ((w = conf_word(fl, 1))) {
		if (have_block && strcmp(w, "devices:") == 0)
			have_devices = 1;
		have_block =  (strcmp(w, "Block") == 0);
		if (isdigit(w[0]))
			last_num = atoi(w);
		if (have_devices && strcmp(w, "mdp") == 0)
			mdp_major = last_num;
		free(w);
	}
	fclose(fl);

	return mdp_major;
}

char *devid2kname(dev_t devid)
{
	char path[30];
	char link[PATH_MAX];
	static char devnm[32];
	char *cp;
	int n;

	/* Look at the
	 * /sys/dev/block/%d:%d link which must look like
	 * and take the last component.
	 */
	sprintf(path, "/sys/dev/block/%d:%d", major(devid), minor(devid));
	n = readlink(path, link, sizeof(link) - 1);
	if (n > 0) {
		link[n] = 0;
		cp = strrchr(link, '/');
		if (cp) {
			snprintf(devnm, sizeof(devnm), "%s", cp + 1);
			return devnm;
		}
	}
	return NULL;
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

char *devid2devnm(dev_t devid)
{
	char path[30];
	char link[200];
	static char devnm[32];
	char *cp, *ep;
	int n;

	/* Might be an extended-minor partition or a
	 * named md device. Look at the
	 * /sys/dev/block/%d:%d link which must look like
	 *    ../../block/mdXXX/mdXXXpYY
	 * or
	 *    ...../block/md_FOO
	 */
	sprintf(path, "/sys/dev/block/%d:%d", major(devid), minor(devid));
	n = readlink(path, link, sizeof(link) - 1);
	if (n > 0) {
		link[n] = 0;
		cp = strstr(link, "/block/");
		if (cp) {
			cp += 7;
			ep = strchr(cp, '/');
			if (ep)
				*ep = 0;
			snprintf(devnm, sizeof(devnm), "%s", cp);
			return devnm;
		}
	}
	if (major(devid) == MD_MAJOR)
		sprintf(devnm,"md%d", minor(devid));
	else if (major(devid) == (unsigned)get_mdp_major())
		sprintf(devnm,"md_d%d",
			(minor(devid)>>MdpMinorShift));
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

/* conf_word gets one word from the conf file.
 * if "allow_key", then accept words at the start of a line,
 * otherwise stop when such a word is found.
 * We assume that the file pointer is at the end of a word, so the
 * next character is a space, or a newline.  If not, it is the start of a line.
 */

char *conf_word(FILE *file, int allow_key)
{
	int wsize = 100;
	int len = 0;
	int c;
	int quote;
	int wordfound = 0;
	char *word = xmalloc(wsize);

	while (wordfound == 0) {
		/* at the end of a word.. */
		c = getc(file);
		if (c == '#')
			while (c != EOF && c != '\n')
				c = getc(file);
		if (c == EOF)
			break;
		if (c == '\n')
			continue;

		if (c != ' ' && c != '\t' && ! allow_key) {
			ungetc(c, file);
			break;
		}
		/* looks like it is safe to get a word here, if there is one */
		quote = 0;
		/* first, skip any spaces */
		while (c == ' ' || c == '\t')
			c = getc(file);
		if (c != EOF && c != '\n' && c != '#') {
			/* we really have a character of a word, so start saving it */
			while (c != EOF && c != '\n' &&
			       (quote || (c != ' ' && c != '\t'))) {
				wordfound = 1;
				if (quote && c == quote)
					quote = 0;
				else if (quote == 0 && (c == '\'' || c == '"'))
					quote = c;
				else {
					if (len == wsize-1) {
						wsize += 100;
						word = xrealloc(word, wsize);
					}
					word[len++] = c;
				}
				c = getc(file);
				/* Hack for broken kernels (2.6.14-.24) that put
				 *        "active(auto-read-only)"
				 * in /proc/mdstat instead of
				 *        "active (auto-read-only)"
				 */
				if (c == '(' && len >= 6 &&
				    strncmp(word + len - 6, "active", 6) == 0)
					c = ' ';
			}
		}
		if (c != EOF)
			ungetc(c, file);
	}
	word[len] = 0;

	/* Further HACK for broken kernels.. 2.6.14-2.6.24 */
	if (strcmp(word, "auto-read-only)") == 0)
		strcpy(word, "(auto-read-only)");

/*    printf("word is <%s>\n", word); */
	if (!wordfound) {
		free(word);
		word = NULL;
	}
	return word;
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

/*
 * conf_line reads one logical line from the conffile or mdstat.
 * It skips comments and continues until it finds a line that starts
 * with a non blank/comment.  This character is pushed back for the next call
 * A doubly linked list of words is returned.
 * the first word will be a keyword.  Other words will have had quotes removed.
 */

char *conf_line(FILE *file)
{
	char *w;
	char *list;

	w = conf_word(file, 1);
	if (w == NULL)
		return NULL;

	list = dl_strdup(w);
	free(w);
	dl_init(list);

	while ((w = conf_word(file, 0))){
		char *w2 = dl_strdup(w);
		free(w);
		dl_add(list, w2);
	}
/*    printf("got a line\n");*/
	return list;
}

void free_line(char *line)
{
	char *w;
	for (w = dl_next(line); w != line; w = dl_next(line)) {
		dl_del(w);
		dl_free(w);
	}
	dl_free(line);
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
