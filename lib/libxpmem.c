/*
 * Copyright (c) 2009 Cray, Inc.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <xpmem.h>

static int xpmem_fd = -1;

/**
 * xpmem_init - Creates an XPMEM file descriptor
 * Description:
 *	Opens XPMEM device file and sets the Close On Exec flag. The device file
 *	descriptor is stored internally for later use with xpmem_ioctl().
 * Context:
 *	xpmem_init() is called by xpmem_ioctl(). This is an internal call--the
 *	user should not need to call this manually.
 * Return Values:
 *	Success: 0
 *	Failure: -1
 */
int xpmem_init(void)
{
	struct stat stb;

/*	if (stat(XPMEM_DEV_PATH, &stb) != 0 ||
	    !S_ISCHR(stb.st_mode) ||
	    (xpmem_fd = open(XPMEM_DEV_PATH, O_RDWR)) == -1 ||
	    fcntl(xpmem_fd, F_SETFD, FD_CLOEXEC) == -1) {
		return -1;
	}*/

    xpmem_fd = open(XPMEM_DEV_PATH, O_RDWR);
    if (xpmem_fd == -1)
        return -1;

    return 0;
}

/**
 * xpmem_ioctl - wrapper for ioctl()
 * @cmd: IN: The command to pass to ioctl()
 * @arg: IN: The argument to pass to ioctl()
 * Description:
 *	Creates an xpmem file descriptor if not present, or use the one
 *	created previously as an argument to ioctl().
 * Context:
 *	xpmem_ioctl() replaces all ioctl() calls in this library. This is an
 *	internal call--the user should not need to call this function manually.
 * Return Values:
 *	Success: not -1
 *	Failure: -1
 */
int xpmem_ioctl(int cmd, void *arg)
{
	int ret;
	if (xpmem_fd == -1 && xpmem_init() != 0)
		return -1;
	ret = ioctl(xpmem_fd, cmd, arg);
	/**
	 * A child process that never opened the XPMEM device, but inherits
	 * xpmem_fd from its parent will have -XPMEM_ERRNO_NOPROC returned. So
	 * simply open the device and retry the ioctl.
	 */
	if (ret == -1 && errno == XPMEM_ERRNO_NOPROC) {
		if ((xpmem_fd = open(XPMEM_DEV_PATH, O_RDWR)) == -1)
			return -1;
		ret = ioctl(xpmem_fd, cmd, arg);
	}
	return ret;
}

/**
 * xpmem_make - share a memory block
 * @vaddr: IN: starting address of region to share
 * @size: IN: number of bytes to share
 * @permit_type: IN: only XPMEM_PERMIT_MODE currently defined
 * @permit_value: IN: permissions mode expressed as an octal value
 * Description:
 *	xpmem_make() shares a memory block by invoking the XPMEM driver.
 * Context:
 *	Called by the source process to obtain a segment ID to share with other
 *	processes.
 * Return Value:
 *	Success: 64-bit segment ID (xpmem_segid_t)
 *	Failure: -1
 */
xpmem_segid_t xpmem_make(void *vaddr, size_t size, int permit_type,
			 void *permit_value)
{
	struct xpmem_cmd_make make_info;

	make_info.vaddr = (__u64)vaddr;
	make_info.size  = size;
    make_info.flags = 0;
	make_info.permit_type  = permit_type;
	make_info.permit_value = (__s64)permit_value;
	if (xpmem_ioctl(XPMEM_CMD_MAKE, &make_info) == -1 || !make_info.segid)
		return -1;
	return make_info.segid;
}

/**
 * xpmem_remove - revoke access to a shared memory block
 * @segid: IN: 64-bit segment ID of the region to stop sharing
 * Description:
 *	The opposite of xpmem_make(), this function deletes the mapping for a
 *	specified segid that was created from a previous xpmem_make() call.
 * Context:
 *	Optionally called by the source process, otherwise automatically called
 *	by the driver when the source process exits.
 * Return Value:
 *	Success: 0
 *	Failure: -1
 */
int xpmem_remove(xpmem_segid_t segid)
{
	struct xpmem_cmd_remove	remove_info;

	remove_info.segid = segid;
	if (xpmem_ioctl(XPMEM_CMD_REMOVE, &remove_info) == -1)
		return -1;
	return 0;
}

/**
 * xpmem_get - obtain permission to attach memory
 * @segid: IN: segment ID returned from a previous xpmem_make() call
 * @flags: IN: read-write (XPMEM_RDWR) or read-only (XPMEM_RDONLY)
 * @permit_type: IN: only XPMEM_PERMIT_MODE currently defined
 * @permit_value: IN: permissions mode expressed as an octal value
 * Description:
 *	xpmem_get() attempts to get access to a shared memory block.
 * Context:
 *	Called by the consumer process to get permission to attach memory from
 *	the source virtual address space associated with this segid. If access
 *	is granted, an apid will be returned to pass to xpmem_attach().
 * Return Value:
 *	Success: 64-bit access permit ID (xpmem_apid_t)
 *	Failure: -1
 */
xpmem_apid_t xpmem_get(xpmem_segid_t segid, int flags, int permit_type,
			void *permit_value)
{
	struct xpmem_cmd_get get_info;

	get_info.segid = segid;
	get_info.flags = flags;
	get_info.permit_type = permit_type;
	get_info.permit_value = (__s64)permit_value;
	if (xpmem_ioctl(XPMEM_CMD_GET, &get_info) == -1 || !get_info.apid)
		return -1;
	return get_info.apid;
}

/**
 * xpmem_release - give up access to the segment
 * @apid: IN: 64-bit access permit ID to release
 * Description:
 *	The opposite of xpmem_get(), this function deletes any mappings in the
 *	consumer's address space.
 * Context:
 *	Optionally called by the consumer process, otherwise automatically
 *	called by the driver when the consumer process exits.
 * Return Value:
 *	Success: 0
 *	Failure: -1
 */
int xpmem_release(xpmem_apid_t apid)
{
	struct xpmem_cmd_release release_info;

	release_info.apid = apid;
	if (xpmem_ioctl(XPMEM_CMD_RELEASE, &release_info) == -1)
		return -1;
	return 0;
}

/**
 * xpmem_attach - map a source address to own address space
 * @addr: IN: a structure consisting of a xpmem_apid_t apid and an off_t offset
 * 	addr.apid: access permit ID returned from a previous xpmem_get() call
 * 	addr.offset: offset into the source memory to begin the mapping
 * @size: IN: number of bytes to map
 * @vaddr: IN: address at which the mapping should be created, or NULL if the
 *		kernel should choose
 * Description:
 *	Attaches a virtual address space range from the source process.
 * Context:
 *	Called by the consumer to get a mapping between the shared source
 *	address and an address in the consumer process' own address space. If
 *	the mapping is successful, then the consumer process can now begin
 *	accessing the shared memory.
 * Return Value:
 *	Success: virtual address at which the mapping was created
 *	Failure: -1
 */
void *xpmem_attach(struct xpmem_addr addr, size_t size, void *vaddr)
{
	struct xpmem_cmd_attach attach_info;

	attach_info.apid = addr.apid;
	attach_info.offset = addr.offset;
	attach_info.size = size;
	attach_info.vaddr = (__u64)vaddr;
	attach_info.fd = xpmem_fd;
	attach_info.flags = 0;
	if (xpmem_ioctl(XPMEM_CMD_ATTACH, &attach_info) == -1)
		return (void *)-1;
	return (void *)attach_info.vaddr;
}

/**
 * xpmem_detach - remove a mapping between consumer and source
 * @vaddr: IN: virtual address within an XPMEM mapping in the consumer's
 *		address space
 * Description:
 *	Detach from the virtual address space of the source process.
 * Context:
 *	Optionally called by the consumer process, otherwise automatically
 *	called by the driver when the consumer process exits.
 * Return Value:
 *	Success: 0
 *	Failure: -1
 */
int xpmem_detach(void *vaddr)
{
	struct xpmem_cmd_detach detach_info;

	detach_info.vaddr = (__u64)vaddr;
	if (xpmem_ioctl(XPMEM_CMD_DETACH, &detach_info) == -1)
		return -1;
	return 0;
}

/**
 * xpmem_version - get the XPMEM version
 *
 * Return Value:
 *	Success: XPMEM version number
 *	Failure: -1
 */
int xpmem_version(void)
{
	return xpmem_ioctl(XPMEM_CMD_VERSION, NULL);
}
