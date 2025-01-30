/*
 * Intel(R) Matrix Storage Manager hardware and firmware support routines
 *
 * Copyright (C) 2008 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "mdadm.h"
#include "platform-intel.h"
#include "probe_roms.h"
#include "xmalloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>

#define NVME_SUBSYS_PATH "/sys/devices/virtual/nvme-subsystem/"

static bool imsm_orom_has_raid0(const struct imsm_orom *orom)
{
	return imsm_rlc_has_bit(orom, IMSM_OROM_RLC_RAID0);
}

static bool imsm_orom_has_raid1(const struct imsm_orom *orom)
{
	return imsm_rlc_has_bit(orom, IMSM_OROM_RLC_RAID1);
}

static bool imsm_orom_has_raid10(const struct imsm_orom *orom)
{
	return imsm_rlc_has_bit(orom, IMSM_OROM_RLC_RAID10);
}

static bool imsm_orom_has_raid5(const struct imsm_orom *orom)
{
	return imsm_rlc_has_bit(orom, IMSM_OROM_RLC_RAID5);
}

/* IMSM platforms do not define how many disks are allowed for each level,
 * but there are some global limitations we need to follow.
 */
static bool imsm_orom_support_raid_disks_count_raid0(const int raid_disks)
{
	return true;
}

static bool imsm_orom_support_raid_disks_count_raid1(const int raid_disks)
{
	if (raid_disks == 2)
		return true;
	return false;
}

static bool imsm_orom_support_raid_disks_count_raid5(const int raid_disks)
{
	if (raid_disks > 2)
		return true;
	return false;
}

static bool imsm_orom_support_raid_disks_count_raid10(const int raid_disks)
{
	/* raid_disks count must be higher than 4 and even */
	if (raid_disks >= 4 && (raid_disks & 1) == 0)
		return true;
	return false;
}

struct imsm_level_ops imsm_level_ops[] = {
		{0, imsm_orom_has_raid0, imsm_orom_support_raid_disks_count_raid0, "raid0"},
		{1, imsm_orom_has_raid1, imsm_orom_support_raid_disks_count_raid1, "raid1"},
		{5, imsm_orom_has_raid5, imsm_orom_support_raid_disks_count_raid5, "raid5"},
		{10, imsm_orom_has_raid10, imsm_orom_support_raid_disks_count_raid10, "raid10"},
		{-1, NULL, NULL, NULL}
};

static int devpath_to_ll(const char *dev_path, const char *entry,
			 unsigned long long *val);

static void free_sys_dev(struct sys_dev **list)
{
	while (*list) {
		struct sys_dev *next = (*list)->next;

		if ((*list)->path)
			free((*list)->path);
		free(*list);
		*list = next;
	}
}

/**
 * vmd_find_pci_bus() - look for PCI bus created by VMD.
 * @vmd_path: path to vmd driver.
 * @buf: return buffer, must be PATH_MAX.
 *
 * Each VMD device represents one domain and each VMD device adds separate PCI bus.
 * IMSM must know VMD domains, therefore it needs to determine and follow buses.
 *
 */
mdadm_status_t vmd_find_pci_bus(char *vmd_path, char *buf)
{
	char tmp[PATH_MAX];
	struct dirent *ent;
	DIR *vmd_dir;
	char *rp_ret;

	snprintf(tmp, PATH_MAX, "%s/domain/device", vmd_path);

	rp_ret = realpath(tmp, buf);

	if (rp_ret)
		return MDADM_STATUS_SUCCESS;

	if (errno != ENOENT)
		return MDADM_STATUS_ERROR;

	/*
	 * If it is done early, there is a chance that kernel is still enumerating VMD device but
	 * kernel did enough to start enumerating child devices, {vmd_path}/domain/device link may
	 * not exist yet. We have to look into @vmd_path directory and find it ourselves.
	 */

	vmd_dir = opendir(vmd_path);

	if (!vmd_dir)
		return MDADM_STATUS_ERROR;

	for (ent = readdir(vmd_dir); ent; ent = readdir(vmd_dir)) {
		static const char pci[] = "pci";

		/**
		 * Pci bus must have form pciXXXXX:XX, where X is a digit i.e pci10000:00.
		 * We do not check digits here, it is sysfs so it should be safe to check
		 * length and ':' position only.
		 */
		if (strncmp(ent->d_name, pci, strlen(pci)) != 0)
			continue;

		if (ent->d_name[8] != ':' || ent->d_name[11] != 0)
			continue;
		break;
	}

	if (!ent) {
		closedir(vmd_dir);
		return MDADM_STATUS_ERROR;
	}

	snprintf(buf, PATH_MAX, "%s/%s", vmd_path, ent->d_name);
	closedir(vmd_dir);
	return MDADM_STATUS_SUCCESS;
}

struct sys_dev *find_driver_devices(const char *bus, const char *driver)
{
	/* search sysfs for devices driven by 'driver' */
	char path[PATH_MAX];
	char link[PATH_MAX];
	char *c;
	DIR *driver_dir;
	struct dirent *de;
	struct sys_dev *head = NULL;
	struct sys_dev *list = NULL;
	struct sys_dev *vmd = NULL;
	enum sys_dev_type type;
	unsigned long long dev_id;
	unsigned long long class;

	if (strcmp(driver, "isci") == 0)
		type = SYS_DEV_SAS;
	else if (strcmp(driver, "ahci") == 0) {
		vmd = find_driver_devices("pci", "vmd");
		type = SYS_DEV_SATA;
	} else if (strcmp(driver, "nvme") == 0) {
		/* if looking for nvme devs, first look for vmd */
		vmd = find_driver_devices("pci", "vmd");
		type = SYS_DEV_NVME;
	} else if (strcmp(driver, "vmd") == 0)
		type = SYS_DEV_VMD;
	else
		type = SYS_DEV_UNKNOWN;

	sprintf(path, "/sys/bus/%s/drivers/%s", bus, driver);
	driver_dir = opendir(path);
	if (!driver_dir) {
		if (vmd)
			free_sys_dev(&vmd);
		return NULL;
	}
	for (de = readdir(driver_dir); de; de = readdir(driver_dir)) {
		int skip = 0;
		char *p;
		int n;

		/* is 'de' a device? check that the 'subsystem' link exists and
		 * that its target matches 'bus'
		 */
		sprintf(path, "/sys/bus/%s/drivers/%s/%s/subsystem",
			bus, driver, de->d_name);
		n = readlink(path, link, sizeof(link));
		if (n < 0 || n >= (int)sizeof(link))
			continue;
		link[n] = '\0';
		c = strrchr(link, '/');
		if (!c)
			continue;
		if (strncmp(bus, c+1, strlen(bus)) != 0)
			continue;

		sprintf(path, "/sys/bus/%s/drivers/%s/%s",
			bus, driver, de->d_name);

		/* if searching for nvme - skip vmd connected one */
		if (type == SYS_DEV_NVME) {
			struct sys_dev *dev;
			char *rp = realpath(path, NULL);
			for (dev = vmd; dev; dev = dev->next) {
				if ((strncmp(dev->path, rp, strlen(dev->path)) == 0))
					skip = 1;
			}
			free(rp);
		}

		/* change sata type if under a vmd controller */
		if (type == SYS_DEV_SATA) {
			struct sys_dev *dev;
			char *rp = realpath(path, NULL);
			for (dev = vmd; dev; dev = dev->next) {
				if ((strncmp(dev->path, rp, strlen(dev->path)) == 0))
					type = SYS_DEV_SATA_VMD;
			}
			free(rp);
		}

		/* if it's not Intel device or mark as VMD connected - skip it. */
		if (devpath_to_vendor(path) != 0x8086 || skip == 1)
			continue;

		if (devpath_to_ll(path, "device", &dev_id) != 0)
			continue;

		if (devpath_to_ll(path, "class", &class) != 0)
			continue;

		if (type == SYS_DEV_VMD) {
			char vmd_path[PATH_MAX];

			sprintf(vmd_path, "/sys/bus/%s/drivers/%s/%s", bus, driver, de->d_name);

			if (vmd_find_pci_bus(vmd_path, path)) {
				pr_err("Cannot determine VMD bus for %s\n", vmd_path);
				continue;
			}
		}

		p = realpath(path, NULL);

		if (!p) {
			pr_err("Unable to get real path for '%s'\n", path);
			continue;
		}

		/* start / add list entry */
		if (!head) {
			head = xmalloc(sizeof(*head));
			list = head;
		} else {
			list->next = xmalloc(sizeof(*head));
			list = list->next;
		}

		if (!list) {
			free_sys_dev(&head);
			break;
		}

		list->dev_id = (__u16) dev_id;
		list->class = (__u32) class;
		list->type = type;
		list->next = NULL;
		list->path = p;

		if ((list->pci_id = strrchr(list->path, '/')) != NULL)
			list->pci_id++;
	}
	closedir(driver_dir);

	/* nvme vmd needs a list separate from sata vmd */
	if (vmd && type == SYS_DEV_NVME) {
		if (list)
			list->next = vmd;
		else
			head = vmd;
	}

	return head;
}

static struct sys_dev *intel_devices=NULL;
static time_t valid_time = 0;

struct sys_dev *device_by_id(__u16 device_id)
{
	struct sys_dev *iter;

	for (iter = intel_devices; iter != NULL; iter = iter->next)
		if (iter->dev_id == device_id)
			return iter;
	return NULL;
}

struct sys_dev *device_by_id_and_path(__u16 device_id, const char *path)
{
	struct sys_dev *iter;

	for (iter = intel_devices; iter != NULL; iter = iter->next)
		if ((iter->dev_id == device_id) && strstr(iter->path, path))
			return iter;
	return NULL;
}

static int devpath_to_ll(const char *dev_path, const char *entry, unsigned long long *val)
{
	char path[strnlen(dev_path, PATH_MAX) + strnlen(entry, PATH_MAX) + 2];
	int fd;
	int n;

	sprintf(path, "%s/%s", dev_path, entry);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = sysfs_fd_get_ll(fd, val);
	close(fd);
	return n;
}

__u16 devpath_to_vendor(const char *dev_path)
{
	char path[strlen(dev_path) + strlen("/vendor") + 1];
	char vendor[7];
	int fd;
	__u16 id = 0xffff;
	int n;

	sprintf(path, "%s/vendor", dev_path);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0xffff;

	n = read(fd, vendor, sizeof(vendor));
	if (n == sizeof(vendor)) {
		vendor[n - 1] = '\0';
		id = strtoul(vendor, NULL, 16);
	}
	close(fd);

	return id;
}

/* Description: Read text value of dev_path/entry field
 * Parameters:
 *	dev_path - sysfs path to the device
 *	entry - entry to be read
 *	buf - buffer for read value
 *	len - size of buf
 *	verbose - error logging level
 */
int devpath_to_char(const char *dev_path, const char *entry, char *buf, int len,
		    int verbose)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", dev_path, entry);
	if (load_sys(path, buf, len)) {
		if (verbose)
			pr_err("Cannot read %s, aborting\n", path);
		return 1;
	}

	return 0;
}

struct sys_dev *find_intel_devices(void)
{
	struct sys_dev *ahci, *isci, *nvme;

	if (valid_time > time(0) - 10)
		return intel_devices;

	if (intel_devices)
		free_sys_dev(&intel_devices);

	isci = find_driver_devices("pci", "isci");
	/* Searching for AHCI will return list of SATA and SATA VMD controllers */
	ahci = find_driver_devices("pci", "ahci");
	/* Searching for NVMe will return list of NVMe and VMD controllers */
	nvme = find_driver_devices("pci", "nvme");

	if (!isci && !ahci) {
		ahci = nvme;
	} else if (!ahci) {
		ahci = isci;
		struct sys_dev *elem = ahci;
		while (elem->next)
			elem = elem->next;
		elem->next = nvme;
	} else {
		struct sys_dev *elem = ahci;
		while (elem->next)
			elem = elem->next;
		elem->next = isci;
		while (elem->next)
			elem = elem->next;
		elem->next = nvme;
	}
	intel_devices = ahci;
	valid_time = time(0);
	return intel_devices;
}

/*
 * PCI Expansion ROM Data Structure Format */
struct pciExpDataStructFormat {
	__u8  ver[4];
	__u16 vendorID;
	__u16 deviceID;
	__u16 devListOffset;
	__u16 pciDataStructLen;
	__u8 pciDataStructRev;
} __attribute__ ((packed));

struct orom_entry *orom_entries;

const struct orom_entry *get_orom_entry_by_device_id(__u16 dev_id)
{
	struct orom_entry *entry;
	struct devid_list *devid;

	for (entry = orom_entries; entry; entry = entry->next) {
		for (devid = entry->devid_list; devid; devid = devid->next) {
			if (devid->devid == dev_id)
				return entry;
		}
	}

	return NULL;
}

const struct imsm_orom *get_orom_by_device_id(__u16 dev_id)
{
	const struct orom_entry *entry = get_orom_entry_by_device_id(dev_id);

	if (entry)
		return &entry->orom;

	return NULL;
}

static struct orom_entry *add_orom(const struct imsm_orom *orom)
{
	struct orom_entry *list;
	struct orom_entry *prev = NULL;

	for (list = orom_entries; list; prev = list, list = list->next)
		;

	list = xmalloc(sizeof(struct orom_entry));
	list->orom = *orom;
	list->devid_list = NULL;
	list->next = NULL;

	if (prev == NULL)
		orom_entries = list;
	else
		prev->next = list;

	return list;
}

static void add_orom_device_id(struct orom_entry *entry, __u16 dev_id)
{
	struct devid_list *list;
	struct devid_list *prev = NULL;

	for (list = entry->devid_list; list; prev = list, list = list->next) {
		if (list->devid == dev_id)
			return;
	}
	list = xmalloc(sizeof(struct devid_list));
	list->devid = dev_id;
	list->next = NULL;

	if (prev == NULL)
		entry->devid_list = list;
	else
		prev->next = list;
}

static int scan(const void *start, const void *end, const void *data)
{
	int offset;
	const struct imsm_orom *imsm_mem = NULL;
	int len = (end - start);
	struct pciExpDataStructFormat *ptr= (struct pciExpDataStructFormat *)data;

	if (data + 0x18 > end) {
		dprintf("cannot find pciExpDataStruct \n");
		return 0;
	}

	dprintf("ptr->vendorID: %lx __le16_to_cpu(ptr->deviceID): %lx \n",
		(ulong) __le16_to_cpu(ptr->vendorID),
		(ulong) __le16_to_cpu(ptr->deviceID));

	if (__le16_to_cpu(ptr->vendorID) != 0x8086)
		return 0;

	if (get_orom_by_device_id(ptr->deviceID))
		return 0;

	for (offset = 0; offset < len; offset += 4) {
		const void *mem = start + offset;

		if ((memcmp(mem, IMSM_OROM_SIGNATURE, 4) == 0)) {
			imsm_mem = mem;
			break;
		}
	}

	if (!imsm_mem)
		return 0;

	struct orom_entry *orom = add_orom(imsm_mem);

	/* only PciDataStructure with revision 3 and above supports devices list. */
	if (ptr->pciDataStructRev >= 3 && ptr->devListOffset) {
		const __u16 *dev_list = (void *)ptr + ptr->devListOffset;
		int i;

		for (i = 0; dev_list[i] != 0; i++)
			add_orom_device_id(orom, dev_list[i]);
	} else {
		add_orom_device_id(orom, __le16_to_cpu(ptr->deviceID));
	}

	return 0;
}

const struct imsm_orom *imsm_platform_test(struct sys_dev *hba)
{
	struct imsm_orom orom = {
		.signature = IMSM_OROM_SIGNATURE,
		.rlc = IMSM_OROM_RLC_RAID0 | IMSM_OROM_RLC_RAID1 |
					IMSM_OROM_RLC_RAID10 | IMSM_OROM_RLC_RAID5,
		.sss = IMSM_OROM_SSS_4kB | IMSM_OROM_SSS_8kB |
					IMSM_OROM_SSS_16kB | IMSM_OROM_SSS_32kB |
					IMSM_OROM_SSS_64kB | IMSM_OROM_SSS_128kB |
					IMSM_OROM_SSS_256kB | IMSM_OROM_SSS_512kB |
					IMSM_OROM_SSS_1MB | IMSM_OROM_SSS_2MB,
		.dpa = IMSM_OROM_DISKS_PER_ARRAY,
		.tds = IMSM_OROM_TOTAL_DISKS,
		.vpa = IMSM_OROM_VOLUMES_PER_ARRAY,
		.vphba = IMSM_OROM_VOLUMES_PER_HBA
	};
	orom.attr = orom.rlc | IMSM_OROM_ATTR_ChecksumVerify;

	if (check_env("IMSM_TEST_OROM_NORAID5")) {
		orom.rlc = IMSM_OROM_RLC_RAID0 | IMSM_OROM_RLC_RAID1 |
				IMSM_OROM_RLC_RAID10;
	}
	if (check_env("IMSM_TEST_AHCI_EFI_NORAID5") && (hba->type == SYS_DEV_SAS)) {
		orom.rlc = IMSM_OROM_RLC_RAID0 | IMSM_OROM_RLC_RAID1 |
				IMSM_OROM_RLC_RAID10;
	}
	if (check_env("IMSM_TEST_SCU_EFI_NORAID5") && (hba->type == SYS_DEV_SATA)) {
		orom.rlc = IMSM_OROM_RLC_RAID0 | IMSM_OROM_RLC_RAID1 |
				IMSM_OROM_RLC_RAID10;
	}

	struct orom_entry *ret = add_orom(&orom);

	add_orom_device_id(ret, hba->dev_id);

	return &ret->orom;
}

static const struct imsm_orom *find_imsm_hba_orom(struct sys_dev *hba)
{
	struct stat st;
	unsigned long align;

	if (check_env("IMSM_TEST_OROM"))
		return imsm_platform_test(hba);

	/* return empty OROM capabilities in EFI test mode */
	if (check_env("IMSM_TEST_AHCI_EFI") || check_env("IMSM_TEST_SCU_EFI"))
		return NULL;

	/* Skip legacy option ROM scan when EFI booted */
	if (stat("/sys/firmware/efi", &st) == 0 && S_ISDIR(st.st_mode))
		return NULL;

	find_intel_devices();

	if (intel_devices == NULL)
		return NULL;

	/* scan option-rom memory looking for an imsm signature */
	if (check_env("IMSM_SAFE_OROM_SCAN"))
		align = 2048;
	else
		align = 512;
	if (probe_roms_init(align) != 0)
		return NULL;
	probe_roms();
	/* ignore return value - True is returned if both adapater roms are found */
	scan_adapter_roms(scan);
	probe_roms_exit();

	return get_orom_by_device_id(hba->dev_id);
}

#define EFI_GUID(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) \
((struct efi_guid) \
{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
  (b) & 0xff, ((b) >> 8) & 0xff, \
  (c) & 0xff, ((c) >> 8) & 0xff, \
  (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})

#define SYS_EFI_VAR_PATH "/sys/firmware/efi/vars"
#define SYS_EFIVARS_PATH "/sys/firmware/efi/efivars"
#define ACPI_TABLES_PATH "/sys/firmware/acpi/tables/"
#define ACPI_UEFI_TABLE_BASE_NAME "UEFI"
#define ACPI_UEFI_DATA_OFFSET 52
#define SCU_PROP "RstScuV"
#define AHCI_PROP "RstSataV"
#define AHCI_SSATA_PROP "RstsSatV"
#define AHCI_TSATA_PROP "RsttSatV"
#define VROC_VMD_PROP "RstUefiV"
#define RST_VMD_PROP "RstVmdV"

#define PCI_CLASS_RAID_CNTRL 0x010400

/* GUID length in Bytes */
#define GUID_LENGTH 16

/* GUID entry in 'UEFI' for Sata controller. */
#define RST_SATA_V_GUID \
	EFI_GUID(0xe4dd92e0, 0xac7d, 0x11df, 0x94, 0xe2, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66)

/* GUID entry in 'UEFI' for sSata controller. */
#define RST_SSATA_V_GUID \
	EFI_GUID(0xb002be42, 0x901d, 0x4018, 0xb4, 0x1e, 0xd7, 0x04, 0xab, 0x3a, 0x0f, 0x15)

/* GUID entry in 'UEFI' for tSata controller. */
#define RST_TSATA_V_GUID \
	EFI_GUID(0x101ce8f1, 0xb873, 0x4362, 0xa9, 0x76, 0xb5, 0x54, 0x31, 0x74, 0x52, 0x7e)

/* GUID entry in 'UEFI' for Intel(R) VROC VMD. */
#define RST_UEFI_V_GUID \
	EFI_GUID(0x4bf2da96, 0xde6e, 0x4d8a, 0xa8, 0x8b, 0xb3, 0xd, 0x33, 0xf6, 0xf, 0x3e)

/**
 * GUID entry in 'UEFI' for Intel(R) RST VMD.
 * Currently is the same like in 'UEFI' for Sata controller.
 */
#define RST_VMD_V_GUID RST_SATA_V_GUID

/* GUID of intel RST vendor EFI var. */
#define INTEL_RST_VENDOR_GUID \
	EFI_GUID(0x193dfefa, 0xa445, 0x4302, 0x99, 0xd8, 0xef, 0x3a, 0xad, 0x1a, 0x04, 0xc6)

/*
 * Unified Extensible Firmware Interface (UEFI) Specification Release 2.10
 * UEFI ACPI DATA TABLE, Table O.1
 */
typedef struct uefi_acpi_table {
	char signature[4];
	__u32 length;
	__u8 revision;
	__u8 checksum;
	char oemid[6];
	/* controller name */
	char oem_table_id[8];
	__u32 oem_revision;
	__u32 creator_id;
	__u32 creator_revision;
	/* controller GUID */
	struct efi_guid identifier;
	/* OROM data offeset */
	__u16 dataOffset;
} uefi_acpi_table_t;

typedef struct uefi_acpi_table_with_orom {
	struct uefi_acpi_table table;
	struct imsm_orom orom;
} uefi_acpi_table_with_orom_t;

/* imsm_orom_id - Identifier used to match imsm efi var or acpi table
 * @name: name of the UEFI property, it is part of efivar name or ACPI table oem_table_id
 * @guid: acpi table guid identifier
 *
 * vendor guid (second part of evifar name) is not added here because it is cost.
 */
typedef struct imsm_orom_id {
	char *name;
	struct efi_guid guid;
} imsm_orom_id_t;

static int read_efi_var(void *buffer, ssize_t buf_size,
			const char *variable_name, struct efi_guid guid)
{
	char path[PATH_MAX];
	char buf[GUID_STR_MAX];
	int fd;
	ssize_t n;

	snprintf(path, PATH_MAX, "%s/%s-%s", SYS_EFIVARS_PATH, variable_name, guid_str(buf, guid));

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 1;

	/* read the variable attributes and ignore it */
	n = read(fd, buf, sizeof(__u32));
	if (n < 0) {
		close(fd);
		return 1;
	}

	/* read the variable data */
	n = read(fd, buffer, buf_size);
	close(fd);
	if (n < buf_size)
		return 1;

	return 0;
}

static int read_efi_variable(void *buffer, ssize_t buf_size,
			     const char *variable_name, struct efi_guid guid)
{
	char path[PATH_MAX];
	char buf[GUID_STR_MAX];
	int dfd;
	ssize_t n, var_data_len;

	/* Try to read the variable using the new efivarfs interface first.
	 * If that fails, fall back to the old sysfs-efivars interface. */
	if (!read_efi_var(buffer, buf_size, variable_name, guid))
		return 0;

	snprintf(path, PATH_MAX, "%s/%s-%s/size", SYS_EFI_VAR_PATH, variable_name, guid_str(buf, guid));

	dprintf("EFI VAR: path=%s\n", path);
	/* get size of variable data */
	dfd = open(path, O_RDONLY);
	if (dfd < 0)
		return 1;

	n = read(dfd, &buf, sizeof(buf));
	close(dfd);
	if (n < 0)
		return 1;
	buf[n] = '\0';

	errno = 0;
	var_data_len = strtoul(buf, NULL, 16);
	if ((errno == ERANGE && (var_data_len == LONG_MAX)) ||
	    (errno != 0 && var_data_len == 0))
		return 1;

	/* get data */
	snprintf(path, PATH_MAX, "%s/%s-%s/data", SYS_EFI_VAR_PATH, variable_name, guid_str(buf, guid));

	dprintf("EFI VAR: path=%s\n", path);
	dfd = open(path, O_RDONLY);
	if (dfd < 0)
		return 1;

	n = read(dfd, buffer, buf_size);
	close(dfd);
	if (n != var_data_len || n < buf_size) {
		return 1;
	}

	return 0;
}

/**
 * is_efi_guid_equal() - check if EFI guids are equal.
 * @guid: EFI guid.
 * @guid1: EFI guid to compare.
 *
 * Return: %true if guid are equal, %false otherwise.
 */
static inline bool is_efi_guid_equal(struct efi_guid guid, struct efi_guid guid1)
{
	if (memcmp(guid.b, guid1.b, GUID_LENGTH) == 0)
		return true;
	return false;
}

/**
 * acpi_any_imsm_orom_id_matching() - match ACPI table with any of given imsm_orom_id.
 * @imsm_orom_ids: array of IMSM OROM Identifiers.
 * @imsm_orom_ids_number: number of IMSM OROM Identifiers.
 * @table: struct with read ACPI UEFI table.
 *
 * Check if read UEFI table contains requested OROM id.
 * EFI GUID and controller name are compared with expected.
 *
 * Return: %true if length is proper table, %false otherwise.
 */
bool acpi_any_imsm_orom_id_matching(imsm_orom_id_t *imsm_orom_ids, int imsm_orom_ids_number,
				    struct uefi_acpi_table table)
{
	int index;

	for (index = 0; index < imsm_orom_ids_number; index++)
		if (strncmp(table.oem_table_id, imsm_orom_ids[index].name,
			    strlen(imsm_orom_ids[index].name)) == 0 &&
		    is_efi_guid_equal(table.identifier,
				      imsm_orom_ids[index].guid) == true)
			return true;
	return false;
}

/**
 * read_uefi_acpi_orom_data() - read OROM data from UEFI ACPI table.
 * @fd: file descriptor.
 * @uefi_table: struct to fill out.
 *
 * Read OROM from ACPI UEFI table under given file descriptor.
 * Table must have the appropriate OROM data, which should be confirmed before call this function.
 * In case of success, &orom in structure in &uefi_table will be filled..
 *
 * Return: %MDADM_STATUS_SUCCESS on success, %MDADM_STATUS_ERROR otherwise.
 */
mdadm_status_t
read_uefi_acpi_orom_data(int fd, uefi_acpi_table_with_orom_t *uefi_table)
{
	assert(is_fd_valid(fd));

	if (lseek(fd, uefi_table->table.dataOffset, 0) == -1L)
		return MDADM_STATUS_ERROR;

	if (read(fd, &uefi_table->orom, sizeof(uefi_table->orom)) == -1)
		return MDADM_STATUS_ERROR;

	return MDADM_STATUS_SUCCESS;
}

/**
 * verify_uefi_acpi_table_length() - verify if ACPI UEFI table have correct length with focus at
 * OROM.
 * @table: struct with UEFI table.
 *
 * Verify if ACPI UEFI table have correct length with focus at OROM. Make sure that the file is
 * correct and contains the appropriate length data based on the length of the OROM.
 *
 * Return: %true if length is correct, %false otherwise.
 */
bool verify_uefi_acpi_table_length(struct uefi_acpi_table table)
{
	if (table.length < ACPI_UEFI_DATA_OFFSET)
		return false;

	if (table.length - table.dataOffset != sizeof(struct imsm_orom))
		return false;
	return true;
}

/**
 * find_orom_in_acpi_uefi_tables() - find OROM in UEFI ACPI tables based on requested OROM ids.
 * @imsm_orom_ids: array of IMSM OROM Identifiers.
 * @imsm_orom_ids_number: number of IMSM OROM Identifiers.
 * @orom: OROM struct buffer to fill out.
 *
 * Find OROM in UEFI ACPI tables provided by Intel, based on requested controllers.
 * The first one to be matched, will be used.
 * If found, the buffer with the OROM structure will be filled.
 *
 * Return: %MDADM_STATUS_SUCCESS on success, %MDADM_STATUS_ERROR otherwise.
 */
mdadm_status_t
find_orom_in_acpi_uefi_tables(imsm_orom_id_t *imsm_orom_ids, int imsm_orom_ids_number,
			      struct imsm_orom *orom)
{
	mdadm_status_t status = MDADM_STATUS_ERROR;
	uefi_acpi_table_with_orom_t uefi_table;
	char path[PATH_MAX];
	struct dirent *ent;
	int fd = -1;
	DIR *dir;

	dir = opendir(ACPI_TABLES_PATH);
	if (!dir)
		return MDADM_STATUS_ERROR;

	for (ent = readdir(dir); ent; ent = readdir(dir)) {
		close_fd(&fd);

		/* Check if file is a UEFI table */
		if (strncmp(ent->d_name, ACPI_UEFI_TABLE_BASE_NAME,
			    strlen(ACPI_UEFI_TABLE_BASE_NAME)) != 0)
			continue;

		snprintf(path, PATH_MAX, "%s/%s", ACPI_TABLES_PATH, ent->d_name);

		fd = open(path, O_RDONLY);
		if (!is_fd_valid(fd)) {
			pr_err("Fail to open ACPI UEFI table file. File: %s, Error: %s\n",
			       ent->d_name, strerror(errno));
			continue;
		}

		if (read(fd, &uefi_table.table, sizeof(struct uefi_acpi_table)) == -1) {
			pr_err("Fail to read IMSM OROM from ACPI UEFI table file. File: %s\n",
			       ent->d_name);
			continue;
		}

		if (!acpi_any_imsm_orom_id_matching(imsm_orom_ids, imsm_orom_ids_number,
						    uefi_table.table))
			continue;

		if (!verify_uefi_acpi_table_length(uefi_table.table))
			continue;

		if (read_uefi_acpi_orom_data(fd, &uefi_table)) {
			pr_err("Fail to read IMSM OROM from ACPI UEFI table file. File: %s\n",
			       ent->d_name);
			continue;
		}

		memcpy(orom, &uefi_table.orom, sizeof(uefi_table.orom));
		status = MDADM_STATUS_SUCCESS;
		break;
	}

	close_fd(&fd);
	closedir(dir);
	return status;
}

/**
 * find_orom_in_efi_variables() - find first IMSM OROM in EFI vars that matches any imsm_orom_id.
 * @imsm_orom_ids: array of IMSM OROM Identifiers.
 * @imsm_orom_ids_number: number of IMSM OROM Identifiers.
 * @orom: OROM struct buffer to fill out.
 *
 * Find IMSM OROM that matches on of imsm_orom_id in EFI variables. The first match is used.
 * If found, the buffer with the OROM structure is filled.
 *
 * Return: %MDADM_STATUS_SUCCESS on success, %MDADM_STATUS_ERROR otherwise.
 */
mdadm_status_t
find_orom_in_efi_variables(imsm_orom_id_t *imsm_orom_ids, int imsm_orom_ids_number,
			   struct imsm_orom *orom)
{
	int index;

	for (index = 0; index < imsm_orom_ids_number; index++)
		if (!read_efi_variable(orom, sizeof(struct imsm_orom), imsm_orom_ids[index].name,
				       INTEL_RST_VENDOR_GUID))
			return MDADM_STATUS_SUCCESS;
	return MDADM_STATUS_ERROR;
}

/**
 * find_imsm_efi_orom() - find OROM for requested controller.
 * @orom: buffer for OROM.
 * @controller_type: requested controller type.
 *
 * Based on controller type, function first search in EFI vars then in ACPI UEFI tables.
 * For each controller there is defined an array of OROM ids from which we can read OROM,
 * the first one to be matched, will be used.
 * In case of success, the structure &orom will be filed out.
 *
 * Return: %MDADM_STATUS_SUCCESS on success.
 */
static mdadm_status_t
find_imsm_efi_orom(struct imsm_orom *orom, enum sys_dev_type controller_type)
{
	static imsm_orom_id_t sata_imsm_orrom_ids[] = {
		{AHCI_PROP, RST_SATA_V_GUID},
		{AHCI_SSATA_PROP, RST_SSATA_V_GUID},
		{AHCI_TSATA_PROP, RST_TSATA_V_GUID},
	};
	static imsm_orom_id_t vmd_imsm_orom_ids[] = {
		{VROC_VMD_PROP, RST_UEFI_V_GUID},
		{RST_VMD_PROP, RST_VMD_V_GUID},
	};
	static imsm_orom_id_t *imsm_orom_ids;
	int imsm_orom_ids_number;

	switch (controller_type) {
	case SYS_DEV_SATA:
		imsm_orom_ids = sata_imsm_orrom_ids;
		imsm_orom_ids_number = ARRAY_SIZE(sata_imsm_orrom_ids);
		break;
	case SYS_DEV_VMD:
	case SYS_DEV_SATA_VMD:
		imsm_orom_ids = vmd_imsm_orom_ids;
		imsm_orom_ids_number = ARRAY_SIZE(vmd_imsm_orom_ids);
		break;
	default:
		return MDADM_STATUS_UNDEF;
	}

	if (!find_orom_in_efi_variables(imsm_orom_ids, imsm_orom_ids_number, orom))
		return MDADM_STATUS_SUCCESS;

	return find_orom_in_acpi_uefi_tables(imsm_orom_ids, imsm_orom_ids_number, orom);
}

const struct imsm_orom *find_imsm_efi(struct sys_dev *hba)
{
	struct imsm_orom orom;
	struct orom_entry *ret;

	if (check_env("IMSM_TEST_AHCI_EFI") || check_env("IMSM_TEST_SCU_EFI"))
		return imsm_platform_test(hba);

	/* OROM test is set, return that there is no EFI capabilities */
	if (check_env("IMSM_TEST_OROM"))
		return NULL;

	switch (hba->type) {
	case SYS_DEV_SAS:
		if (!read_efi_variable(&orom, sizeof(orom), SCU_PROP, INTEL_RST_VENDOR_GUID))
			break;
		return NULL;
	case SYS_DEV_SATA:
		if (hba->class != PCI_CLASS_RAID_CNTRL)
			return NULL;

		if (find_imsm_efi_orom(&orom, hba->type))
			return NULL;
		break;
	case SYS_DEV_VMD:
	case SYS_DEV_SATA_VMD:
		if (find_imsm_efi_orom(&orom, hba->type))
			return NULL;
		break;
	default:
		return NULL;
	}

	ret = add_orom(&orom);
	add_orom_device_id(ret, hba->dev_id);
	ret->type = hba->type;

	return &ret->orom;
}

const struct imsm_orom *find_imsm_nvme(struct sys_dev *hba)
{
	static struct orom_entry *nvme_orom;

	if (hba->type != SYS_DEV_NVME)
		return NULL;

	if (!nvme_orom) {
		struct imsm_orom nvme_orom_compat = {
			.signature = IMSM_NVME_OROM_COMPAT_SIGNATURE,
			.rlc = IMSM_OROM_RLC_RAID0 | IMSM_OROM_RLC_RAID1 |
						IMSM_OROM_RLC_RAID10 | IMSM_OROM_RLC_RAID5,
			.sss = IMSM_OROM_SSS_4kB | IMSM_OROM_SSS_8kB |
						IMSM_OROM_SSS_16kB | IMSM_OROM_SSS_32kB |
						IMSM_OROM_SSS_64kB | IMSM_OROM_SSS_128kB,
			.dpa = IMSM_OROM_DISKS_PER_ARRAY_NVME,
			.tds = IMSM_OROM_TOTAL_DISKS_NVME,
			.vpa = IMSM_OROM_VOLUMES_PER_ARRAY,
			.vphba = IMSM_OROM_TOTAL_DISKS_NVME / 2 * IMSM_OROM_VOLUMES_PER_ARRAY,
			.attr = IMSM_OROM_ATTR_2TB | IMSM_OROM_ATTR_2TB_DISK,
			.driver_features = IMSM_OROM_CAPABILITIES_EnterpriseSystem |
					   IMSM_OROM_CAPABILITIES_TPV
		};
		nvme_orom = add_orom(&nvme_orom_compat);
	}
	add_orom_device_id(nvme_orom, hba->dev_id);
	nvme_orom->type = SYS_DEV_NVME;
	return &nvme_orom->orom;
}

#define VMD_REGISTER_OFFSET		0x3FC
#define VMD_REGISTER_SKU_SHIFT		1
#define VMD_REGISTER_SKU_MASK		(0x00000007)
#define VMD_REGISTER_SKU_PREMIUM	2
#define MD_REGISTER_VER_MAJOR_SHIFT	4
#define MD_REGISTER_VER_MAJOR_MASK	(0x0000000F)
#define MD_REGISTER_VER_MINOR_SHIFT	8
#define MD_REGISTER_VER_MINOR_MASK	(0x0000000F)

/*
 * read_vmd_register() - Reads VMD register and writes contents to buff ptr
 * @buff: buffer for vmd register data, should be the size of uint32_t
 *
 * Return: 0 on success, 1 on error
 */
int read_vmd_register(uint32_t *buff, struct sys_dev *hba)
{
	int fd;
	char vmd_pci_config_path[PATH_MAX];

	if (!vmd_domain_to_controller(hba, vmd_pci_config_path))
		return 1;

	strncat(vmd_pci_config_path, "/config", PATH_MAX - strnlen(vmd_pci_config_path, PATH_MAX));

	fd = open(vmd_pci_config_path, O_RDONLY);
	if (fd < 0)
		return 1;

	if (pread(fd, buff, sizeof(uint32_t), VMD_REGISTER_OFFSET) != sizeof(uint32_t)) {
		close(fd);
		return 1;
	}
	close(fd);
	return 0;
}

/*
 * add_vmd_orom() - Adds VMD orom cap to orom list, writes orom_entry ptr into vmd_orom
 * @vmd_orom: pointer to orom entry pointer
 *
 * Return: 0 on success, 1 on error
 */
int add_vmd_orom(struct orom_entry **vmd_orom, struct sys_dev *hba)
{
	uint8_t sku;
	uint32_t vmd_register_data;
	struct imsm_orom vmd_orom_cap = {
		.signature = IMSM_VMD_OROM_COMPAT_SIGNATURE,
		.sss = IMSM_OROM_SSS_4kB | IMSM_OROM_SSS_8kB |
					IMSM_OROM_SSS_16kB | IMSM_OROM_SSS_32kB |
					IMSM_OROM_SSS_64kB | IMSM_OROM_SSS_128kB,
		.dpa = IMSM_OROM_DISKS_PER_ARRAY_NVME,
		.tds = IMSM_OROM_TOTAL_DISKS_VMD,
		.vpa = IMSM_OROM_VOLUMES_PER_ARRAY,
		.vphba = IMSM_OROM_VOLUMES_PER_HBA_VMD,
		.attr = IMSM_OROM_ATTR_2TB | IMSM_OROM_ATTR_2TB_DISK,
		.driver_features = IMSM_OROM_CAPABILITIES_EnterpriseSystem |
				   IMSM_OROM_CAPABILITIES_TPV
	};

	if (read_vmd_register(&vmd_register_data, hba) != 0)
		return 1;

	sku = (uint8_t)((vmd_register_data >> VMD_REGISTER_SKU_SHIFT) &
		VMD_REGISTER_SKU_MASK);

	if (sku == VMD_REGISTER_SKU_PREMIUM)
		vmd_orom_cap.rlc = IMSM_OROM_RLC_RAID0 | IMSM_OROM_RLC_RAID1 |
				   IMSM_OROM_RLC_RAID10 | IMSM_OROM_RLC_RAID5;
	else
		vmd_orom_cap.rlc = IMSM_OROM_RLC_RAID_CNG;

	vmd_orom_cap.major_ver = (uint8_t)
		((vmd_register_data >> MD_REGISTER_VER_MAJOR_SHIFT) &
			MD_REGISTER_VER_MAJOR_MASK);
	vmd_orom_cap.minor_ver = (uint8_t)
		((vmd_register_data >> MD_REGISTER_VER_MINOR_SHIFT) &
			MD_REGISTER_VER_MINOR_MASK);

	*vmd_orom = add_orom(&vmd_orom_cap);

	return 0;
}

const struct imsm_orom *find_imsm_vmd(struct sys_dev *hba)
{
	static struct orom_entry *vmd_orom;

	if (hba->type != SYS_DEV_VMD)
		return NULL;

	if (!vmd_orom && add_vmd_orom(&vmd_orom, hba) != 0)
		return NULL;

	add_orom_device_id(vmd_orom, hba->dev_id);
	vmd_orom->type = SYS_DEV_VMD;
	return &vmd_orom->orom;
}

const struct imsm_orom *find_imsm_capability(struct sys_dev *hba)
{
	const struct imsm_orom *cap = get_orom_by_device_id(hba->dev_id);

	if (cap)
		return cap;

	if (hba->type == SYS_DEV_NVME)
		return find_imsm_nvme(hba);

	cap = find_imsm_efi(hba);
	if (cap)
		return cap;

	if (hba->type == SYS_DEV_VMD) {
		cap = find_imsm_vmd(hba);
		if (cap)
			return cap;
	}

	cap = find_imsm_hba_orom(hba);
	if (cap)
		return cap;

	return NULL;
}

/* Check whether the nvme device is represented by nvme subsytem,
 * if yes virtual path should be changed to hardware device path,
 * to allow IMSM capabilities detection.
 * Returns:
 *	hardware path to device - if the device is represented via
 *		nvme virtual subsytem
 *	NULL - if the device is not represented via nvme virtual subsytem
 */
char *get_nvme_multipath_dev_hw_path(const char *dev_path)
{
	DIR *dir;
	struct dirent *ent;
	char *rp = NULL;

	if (strncmp(dev_path, NVME_SUBSYS_PATH, strlen(NVME_SUBSYS_PATH)) != 0)
		return NULL;

	dir = opendir(dev_path);
	if (!dir)
		return NULL;

	for (ent = readdir(dir); ent; ent = readdir(dir)) {
		char buf[PATH_MAX];

		/* Check if dir is a controller, ignore namespaces*/
		if (!(strncmp(ent->d_name, "nvme", 4) == 0) ||
		    (strrchr(ent->d_name, 'n') != &ent->d_name[0]))
			continue;

		snprintf(buf, PATH_MAX, "%s/%s", dev_path, ent->d_name);
		rp = realpath(buf, NULL);
		break;
	}

	closedir(dir);
	return rp;
}

/* Description: Return part or whole realpath for the dev
 * Parameters:
 *	dev - the device to be quered
 *	dev_level - level of "/device" entries. It allows to caller to access
 *		    virtual or physical devices which are on "path" to quered
 *		    one.
 *	buf - optional, must be PATH_MAX size. If set, then will be used.
 */
char *devt_to_devpath(dev_t dev, int dev_level, char *buf)
{
	char device[PATH_MAX];
	char *hw_path;
	int i;
	unsigned long device_free_len = sizeof(device) - 1;
	char dev_str[] = "/device";
	unsigned long dev_str_len = strlen(dev_str);

	snprintf(device, sizeof(device), "/sys/dev/block/%d:%d", major(dev),
		 minor(dev));

	/* If caller wants block device, return path to it even if it is exposed
	 * via virtual layer.
	 */
	if (dev_level == 0)
		return realpath(device, buf);

	device_free_len -= strlen(device);
	for (i = 0; i < dev_level; i++) {
		if (device_free_len < dev_str_len)
			return NULL;

		strncat(device, dev_str, device_free_len);

		/* Resolve nvme-subsystem abstraction if needed
		 */
		device_free_len -= dev_str_len;
		if (i == 0) {
			char rp[PATH_MAX];

			if (!realpath(device, rp))
				return NULL;
			hw_path = get_nvme_multipath_dev_hw_path(rp);
			if (hw_path) {
				strcpy(device, hw_path);
				device_free_len = sizeof(device) -
						  strlen(device) - 1;
				free(hw_path);
			}
		}
	}

	return realpath(device, buf);
}

char *diskfd_to_devpath(int fd, int dev_level, char *buf)
{
	/* return the device path for a disk, return NULL on error or fd
	 * refers to a partition
	 */
	struct stat st;

	if (fstat(fd, &st) != 0)
		return NULL;
	if (!S_ISBLK(st.st_mode))
		return NULL;

	return devt_to_devpath(st.st_rdev, dev_level, buf);
}
/**
 * is_path_attached_to_hba() - Check if disk is attached to hba
 *
 * @disk_path: Path to disk.
 * @hba_path: Path to hba.
 *
 * Returns: true if disk is attached to hba, false otherwise.
 */
bool is_path_attached_to_hba(const char *disk_path, const char *hba_path)
{
	if (!disk_path || !hba_path)
		return false;
	if (strncmp(disk_path, hba_path, strlen(hba_path)) == 0)
		return true;

	return false;
}

int devt_attached_to_hba(dev_t dev, const char *hba_path)
{
	char *disk_path = devt_to_devpath(dev, 1, NULL);
	int rc = is_path_attached_to_hba(disk_path, hba_path);

	if (disk_path)
		free(disk_path);

	return rc;
}

int disk_attached_to_hba(int fd, const char *hba_path)
{
	char *disk_path = diskfd_to_devpath(fd, 1, NULL);
	int rc = is_path_attached_to_hba(disk_path, hba_path);

	if (disk_path)
		free(disk_path);

	return rc;
}

char *vmd_domain_to_controller(struct sys_dev *hba, char *buf)
{
	struct dirent *ent;
	DIR *dir;
	char path[PATH_MAX];

	if (!hba)
		return NULL;

	if (hba->type != SYS_DEV_VMD)
		return NULL;

	dir = opendir("/sys/bus/pci/drivers/vmd");
	if (!dir)
		return NULL;

	for (ent = readdir(dir); ent; ent = readdir(dir)) {
		sprintf(path, "/sys/bus/pci/drivers/vmd/%s/domain/device",
			ent->d_name);

		if (!realpath(path, buf))
			continue;

		if (strncmp(buf, hba->path, strlen(buf)) == 0) {
			sprintf(path, "/sys/bus/pci/drivers/vmd/%s", ent->d_name);
			closedir(dir);
			return realpath(path, buf);
		}
	}

	closedir(dir);
	return NULL;
}

/* Scan over all controller's namespaces and compare nsid value to verify if
 * current one is supported. The routine doesn't check IMSM capabilities for
 * namespace. Only one nvme namespace is supported by IMSM.
 * Paramteres:
 *	fd - open descriptor to the nvme namespace
 *	verbose - error logging level
 * Returns:
 *	1 - if namespace is supported
 *	0 - otherwise
 */
int imsm_is_nvme_namespace_supported(int fd, int verbose)
{
	DIR *dir = NULL;
	struct dirent *ent;
	char cntrl_path[PATH_MAX];
	char ns_path[PATH_MAX];
	unsigned long long lowest_nsid = ULLONG_MAX;
	unsigned long long this_nsid;
	int rv = 0;


	if (!diskfd_to_devpath(fd, 1, cntrl_path) ||
	    !diskfd_to_devpath(fd, 0, ns_path)) {
		if (verbose)
			pr_err("Cannot get device paths\n");
		goto abort;
	}


	if (devpath_to_ll(ns_path, "nsid", &this_nsid)) {
		if (verbose)
			pr_err("Cannot read nsid value for %s",
			       basename(ns_path));
		goto abort;
	}

	dir = opendir(cntrl_path);
	if (!dir)
		goto abort;

	/* The lowest nvme namespace is supported */
	for (ent = readdir(dir); ent; ent = readdir(dir)) {
		unsigned long long curr_nsid;
		char curr_ns_path[PATH_MAX + 256];

		if (!strstr(ent->d_name, "nvme"))
			continue;

		snprintf(curr_ns_path, sizeof(curr_ns_path), "%s/%s",
			 cntrl_path, ent->d_name);

		if (devpath_to_ll(curr_ns_path, "nsid", &curr_nsid))
			goto abort;

		if (lowest_nsid > curr_nsid)
			lowest_nsid = curr_nsid;
	}

	if (this_nsid == lowest_nsid)
		rv = 1;
	else if (verbose)
		pr_err("IMSM is supported on the lowest NVMe namespace\n");

abort:
	if (dir)
		closedir(dir);

	return rv;
}

/* Verify if multipath is supported by NVMe controller
 * Returns:
 *	0 - not supported
 *	1 - supported
 */
int is_multipath_nvme(int disk_fd)
{
	char ns_path[PATH_MAX];

	if (!diskfd_to_devpath(disk_fd, 0, ns_path))
		return 0;

	if (strncmp(ns_path, NVME_SUBSYS_PATH, strlen(NVME_SUBSYS_PATH)) == 0)
		return 1;

	return 0;
}
