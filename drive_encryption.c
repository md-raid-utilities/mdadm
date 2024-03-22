// SPDX-License-Identifier: GPL-2.0-only
/*
 * Read encryption information for Opal and ATA devices.
 *
 * Copyright (C) 2024 Intel Corporation
 *	Author: Blazej Kucman <blazej.kucman@intel.com>
 */

#include "mdadm.h"

#include <asm/types.h>
#include <linux/nvme_ioctl.h>
#include "drive_encryption.h"

/*
 * Opal defines
 * TCG Storage Opal SSC 2.01 chapter 3.3.3
 * NVM ExpressTM Revision 1.4c, chapter 5
 */
#define TCG_SECP_01 (0x01)
#define TCG_SECP_00 (0x00)
#define OPAL_DISCOVERY_COMID (0x0001)
#define OPAL_LOCKING_FEATURE (0x0002)
#define OPAL_IO_BUFFER_LEN 2048
#define OPAL_DISCOVERY_FEATURE_HEADER_LEN (4)

/*
 * NVMe defines
 * NVM ExpressTM Revision 1.4c, chapter 5
 */
#define NVME_SECURITY_RECV (0x82)
#define NVME_IDENTIFY (0x06)
#define NVME_IDENTIFY_RESPONSE_LEN 4096
#define NVME_OACS_BYTE_POSITION (256)
#define NVME_IDENTIFY_CONTROLLER_DATA (1)

typedef enum drive_feature_support_status {
	/* Drive feature is supported. */
	DRIVE_FEAT_SUP_ST = 0,
	/* Drive feature is not supported. */
	DRIVE_FEAT_NOT_SUP_ST,
	/* Drive feature support check failed. */
	DRIVE_FEAT_CHECK_FAILED_ST
} drive_feat_sup_st;

/* TCG Storage Opal SSC 2.01 chapter 3.1.1.3 */
typedef struct opal_locking_feature {
	/* feature header */
	__u16 feature_code;
	__u8 reserved : 4;
	__u8 version : 4;
	__u8 description_length;
	/* feature description */
	__u8 locking_supported : 1;
	__u8 locking_enabled : 1;
	__u8 locked : 1;
	__u8 media_encryption : 1;
	__u8 mbr_enabled : 1;
	__u8 mbr_done : 1;
	__u8 mbr_shadowing_not_supported : 1;
	__u8 hw_reset_for_dor_supported : 1;
	__u8 reserved1[11];
} __attribute__((__packed__)) opal_locking_feature_t;

/* TCG Storage Opal SSC 2.01 chapter 3.1.1.1 */
typedef struct opal_level0_header {
	__u32 length;
	__u32 version;
	__u64 reserved;
	__u8 vendor_specific[32];
} opal_level0_header_t;

/**
 * NVM ExpressTM Revision 1.4c, Figure 249
 * Structure specifies only OACS filed, which is needed in the current use case.
 */
typedef struct nvme_identify_ctrl {
	__u8 reserved[255];
	__u16 oacs;
	__u8 reserved2[3839];
} nvme_identify_ctrl_t;

/* SCSI Primary Commands - 4 (SPC-4), Table 512 */
typedef struct supported_security_protocols {
	__u8  reserved[6];
	__u16 list_length;
	__u8  list[504];
} supported_security_protocols_t;

/**
 * get_opal_locking_feature_description() - get opal locking feature description.
 * @response: response from Opal Discovery Level 0.
 *
 * Based on the documentation TCG Storage Opal SSC 2.01 chapter 3.1.1,
 * a Locking feature is searched for in Opal Level 0 Discovery response.
 *
 * Return: if locking feature is found, pointer to struct %opal_locking_feature_t, NULL otherwise.
 */
static opal_locking_feature_t *get_opal_locking_feature_description(__u8 *response)
{
	opal_level0_header_t *response_header = (opal_level0_header_t *)response;
	int features_length = __be32_to_cpu(response_header->length);
	int current_position = sizeof(*response_header);

	while (current_position < features_length) {
		opal_locking_feature_t *feature;

		feature = (opal_locking_feature_t *)(response + current_position);

		if (__be16_to_cpu(feature->feature_code) == OPAL_LOCKING_FEATURE)
			return feature;

		current_position += feature->description_length + OPAL_DISCOVERY_FEATURE_HEADER_LEN;
	}

	return NULL;
}

/**
 * nvme_security_recv_ioctl() - nvme security receive ioctl.
 * @disk_fd: a disk file descriptor.
 * @sec_protocol: security protocol.
 * @comm_id: command id.
 * @response_buffer: response buffer to fill out.
 * @buf_size: response buffer size.
 * @verbose: verbose flag.
 *
 * Based on the documentations TCG Storage Opal SSC 2.01 chapter 3.3.3 and
 * NVM ExpressTM Revision 1.4c, chapter 5.25,
 * read security receive command via ioctl().
 * On success, @response_buffer is completed.
 *
 * Return: %MDADM_STATUS_SUCCESS on success, %MDADM_STATUS_ERROR otherwise.
 */
static mdadm_status_t
nvme_security_recv_ioctl(int disk_fd, __u8 sec_protocol, __u16 comm_id, void *response_buffer,
			 size_t buf_size, const int verbose)
{
	struct nvme_admin_cmd nvme_cmd = {0};
	int status;

	nvme_cmd.opcode = NVME_SECURITY_RECV;
	nvme_cmd.cdw10 = sec_protocol << 24 | comm_id << 8;
	nvme_cmd.cdw11 = buf_size;
	nvme_cmd.data_len = buf_size;
	nvme_cmd.addr = (__u64)response_buffer;

	status = ioctl(disk_fd, NVME_IOCTL_ADMIN_CMD, &nvme_cmd);
	if (status != 0) {
		pr_vrb("Failed to read NVMe security receive ioctl() for device /dev/%s, status: %d\n",
		       fd2kname(disk_fd), status);
		return MDADM_STATUS_ERROR;
	}

	return MDADM_STATUS_SUCCESS;
}

/**
 * nvme_identify_ioctl() - NVMe identify ioctl.
 * @disk_fd: a disk file descriptor.
 * @response_buffer: response buffer to fill out.
 * @buf_size: response buffer size.
 * @verbose: verbose flag.
 *
 * Based on the documentations TCG Storage Opal SSC 2.01 chapter 3.3.3 and
 * NVM ExpressTM Revision 1.4c, chapter 5.25,
 * read NVMe identify via ioctl().
 * On success, @response_buffer will be completed.
 *
 * Return: %MDADM_STATUS_SUCCESS on success, %MDADM_STATUS_ERROR otherwise.
 */
static mdadm_status_t
nvme_identify_ioctl(int disk_fd, void *response_buffer, size_t buf_size, const int verbose)
{
	struct nvme_admin_cmd nvme_cmd = {0};
	int status;

	nvme_cmd.opcode = NVME_IDENTIFY;
	nvme_cmd.cdw10 = NVME_IDENTIFY_CONTROLLER_DATA;
	nvme_cmd.data_len = buf_size;
	nvme_cmd.addr = (__u64)response_buffer;

	status = ioctl(disk_fd, NVME_IOCTL_ADMIN_CMD, &nvme_cmd);
	if (status != 0) {
		pr_vrb("Failed to read NVMe identify ioctl() for device /dev/%s, status: %d\n",
		       fd2kname(disk_fd), status);
		return MDADM_STATUS_ERROR;
	}

	return MDADM_STATUS_SUCCESS;
}

/**
 * is_sec_prot_01h_supported() - check if security protocol 01h supported.
 * @security_protocols: struct with response from disk (NVMe, SATA) describing supported
 * security protocols.
 *
 * Return: true if TCG_SECP_01 found, false otherwise.
 */
static bool is_sec_prot_01h_supported(supported_security_protocols_t *security_protocols)
{
	int list_length = be16toh(security_protocols->list_length);
	int index;

	for (index = 0 ; index < list_length; index++) {
		if (security_protocols->list[index] == TCG_SECP_01)
			return true;
	}

	return false;
}

/**
 * is_sec_prot_01h_supported_nvme() - check if security protocol 01h supported for given NVMe disk.
 * @disk_fd: a disk file descriptor.
 * @verbose: verbose flag.
 *
 * Return: %DRIVE_FEAT_SUP_ST if TCG_SECP_01 supported, %DRIVE_FEAT_NOT_SUP_ST if not supported,
 * %DRIVE_FEAT_CHECK_FAILED_ST if failed to check.
 */
static drive_feat_sup_st is_sec_prot_01h_supported_nvme(int disk_fd, const int verbose)
{
	supported_security_protocols_t security_protocols = {0};

	/* security_protocol: TCG_SECP_00, comm_id: not applicable */
	if (nvme_security_recv_ioctl(disk_fd, TCG_SECP_00, 0x0, &security_protocols,
				     sizeof(security_protocols), verbose))
		return DRIVE_FEAT_CHECK_FAILED_ST;

	if (is_sec_prot_01h_supported(&security_protocols))
		return DRIVE_FEAT_SUP_ST;

	return DRIVE_FEAT_NOT_SUP_ST;
}

/**
 * is_nvme_sec_send_recv_supported() - check if Security Send and Security Receive is supported.
 * @disk_fd: a disk file descriptor.
 * @verbose: verbose flag.
 *
 * Check if "Optional Admin Command Support" bit 0 is set in NVMe identify.
 * Bit 0 set to 1 means controller supports the Security Send and Security Receive commands.
 *
 * Return: %DRIVE_FEAT_SUP_ST if security send/receive supported,
 * %DRIVE_FEAT_NOT_SUP_ST if not supported, %DRIVE_FEAT_CHECK_FAILED_ST if check failed.
 */
static drive_feat_sup_st is_nvme_sec_send_recv_supported(int disk_fd, const int verbose)
{
	nvme_identify_ctrl_t nvme_identify = {0};
	int status = 0;

	status = nvme_identify_ioctl(disk_fd, &nvme_identify, sizeof(nvme_identify), verbose);
	if (status)
		return DRIVE_FEAT_CHECK_FAILED_ST;

	if ((__le16_to_cpu(nvme_identify.oacs) & 0x1) == 0x1)
		return DRIVE_FEAT_SUP_ST;

	return DRIVE_FEAT_NOT_SUP_ST;
}

/**
 * get_opal_encryption_information() - get Opal encryption information.
 * @buffer: buffer with Opal Level 0 Discovery response.
 * @information: struct to fill out, describing encryption status of disk.
 *
 * If Locking feature frame is in response from Opal Level 0 discovery, &encryption_information_t
 * structure is completed with status and ability otherwise the status is set to &None.
 * For possible encryption statuses and abilities,
 * please refer to enums &encryption_status and &encryption_ability.
 *
 * Return: %MDADM_STATUS_SUCCESS on success, %MDADM_STATUS_ERROR otherwise.
 */
static mdadm_status_t get_opal_encryption_information(__u8 *buffer,
						      encryption_information_t *information)
{
	opal_locking_feature_t *opal_locking_feature =
					get_opal_locking_feature_description(buffer);

	if (!opal_locking_feature)
		return MDADM_STATUS_ERROR;

	if (opal_locking_feature->locking_supported == 1) {
		information->ability = ENC_ABILITY_SED;

		if (opal_locking_feature->locking_enabled == 0)
			information->status = ENC_STATUS_UNENCRYPTED;
		else if (opal_locking_feature->locked == 1)
			information->status = ENC_STATUS_LOCKED;
		else
			information->status = ENC_STATUS_UNLOCKED;
	} else {
		information->ability = ENC_ABILITY_NONE;
		information->status = ENC_STATUS_UNENCRYPTED;
	}

	return MDADM_STATUS_SUCCESS;
}

/**
 * get_nvme_opal_encryption_information() - get NVMe Opal encryption information.
 * @disk_fd: a disk file descriptor.
 * @information: struct to fill out, describing encryption status of disk.
 * @verbose: verbose flag.
 *
 * In case the disk supports Opal Level 0 discovery, &encryption_information_t structure
 * is completed with status and ability based on ioctl response,
 * otherwise the ability is set to %ENC_ABILITY_NONE and &status to %ENC_STATUS_UNENCRYPTED.
 * As the current use case does not need the knowledge of Opal support, if there is no support,
 * %MDADM_STATUS_SUCCESS will be returned, with the values described above.
 * For possible encryption statuses and abilities,
 * please refer to enums &encryption_status and &encryption_ability.
 *
 * %MDADM_STATUS_SUCCESS on success, %MDADM_STATUS_ERROR otherwise.
 */
mdadm_status_t
get_nvme_opal_encryption_information(int disk_fd, encryption_information_t *information,
				     const int verbose)
{
	__u8 buffer[OPAL_IO_BUFFER_LEN];
	int sec_send_recv_supported = 0;
	int protocol_01h_supported = 0;
	mdadm_status_t status;

	information->ability = ENC_ABILITY_NONE;
	information->status = ENC_STATUS_UNENCRYPTED;

	sec_send_recv_supported = is_nvme_sec_send_recv_supported(disk_fd, verbose);
	if (sec_send_recv_supported == DRIVE_FEAT_CHECK_FAILED_ST)
		return MDADM_STATUS_ERROR;

	/* Opal not supported */
	if (sec_send_recv_supported == DRIVE_FEAT_NOT_SUP_ST)
		return MDADM_STATUS_SUCCESS;

	/**
	 * sec_send_recv_supported determine that it should be possible to read
	 * supported sec protocols
	 */
	protocol_01h_supported = is_sec_prot_01h_supported_nvme(disk_fd, verbose);
	if (protocol_01h_supported == DRIVE_FEAT_CHECK_FAILED_ST)
		return MDADM_STATUS_ERROR;

	/* Opal not supported */
	if (sec_send_recv_supported == DRIVE_FEAT_SUP_ST &&
	    protocol_01h_supported == DRIVE_FEAT_NOT_SUP_ST)
		return MDADM_STATUS_SUCCESS;

	if (nvme_security_recv_ioctl(disk_fd, TCG_SECP_01, OPAL_DISCOVERY_COMID, (void *)&buffer,
				     OPAL_IO_BUFFER_LEN, verbose))
		return MDADM_STATUS_ERROR;

	status = get_opal_encryption_information((__u8 *)&buffer, information);
	if (status)
		pr_vrb("Locking feature description not found in Level 0 discovery response. Device /dev/%s.\n",
		       fd2kname(disk_fd));

	if (information->ability == ENC_ABILITY_NONE)
		assert(information->status == ENC_STATUS_UNENCRYPTED);

	return status;
}
