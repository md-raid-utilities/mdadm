/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * md_common - constants shared between md driver abstractions.
 */

#ifndef MD_COMMON_H
#define MD_COMMON_H

/*
 * Prefix used by the md driver version to mark an externally-managed array or
 * container. The full form is:
 *
 *   "external:" [/-] containername [/subarray]
 *
 * The '/' or '-' separator distinguishes normal read-write arrays from those
 * that mdmon must not reconfigure (read-only, reshaping, etc.).
 */
#define MD_EXT                  "external" /* The external keyword used in various contexts */

#define MD_VER_EXT	        "external:" /* The "external:" version const prefix */
#define MD_VER_EXT_LEN	(sizeof(MD_VER_EXT) - 1) /* Length of external prefix */

/* Index of the character that blocks the version.
 * It is the one after the prefix so the array index is MD_VER_EXT_LEN
 */
#define MD_VER_BLOCKED_IDX (MD_VER_EXT_LEN)

#endif
