/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef MAPFILE_H
#define MAPFILE_H

/*
 * The directory for mdadm maps, customizable at compile time.
 *
 * it has to persist across the pivotroot from early boot to late boot.
 * /run seems to have emerged as the best standard.
 */
#ifndef MAP_DIR
#define MAP_DIR "/run/mdadm"
#endif /* MAP_DIR */

/* The name of the file put in MAP_DIR, customizable at compile time. */
#ifndef MAP_FILE
#define MAP_FILE "map"
#endif /* MAP_FILE */

struct map_ent {
	struct map_ent *next;
	char metadata[20];
	char devnm[32];
	int uuid[4];
	char *path;
	int bad;
};

void map_fork(void);
void map_free(struct map_ent *map);

void map_add(struct map_ent **mpp, char *devnm, char *metadata, int uuid[4], char *path);
void map_delete(struct map_ent **mpp, char *devnm);
void map_remove(struct map_ent **mpp, char *devnm);
int map_update(struct map_ent **mpp, char *devnm, char *metadata, int uuid[4], char *path);

struct map_ent *map_by_devnm(struct map_ent **mpp, char *devnm);
struct map_ent *map_by_name(struct map_ent **mpp, char *name);
struct map_ent *map_by_uuid(struct map_ent **mpp, int uuid[4]);

void map_read(struct map_ent **mpp);
int map_write(struct map_ent *map);

int map_lock(struct map_ent **mpp);
void map_unlock(struct map_ent **mpp);

#endif // MAPFILE_H
