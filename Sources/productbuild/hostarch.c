/*
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Derive the hostArchitectures an installer package advertises.  The
 * value comes from the bundle's main executable: Installer reports the
 * architectures it can run the bundle on, so a fat binary yields every
 * slice it carries (arm64e counts as arm64) while helper tools shipped
 * inside Resources are irrelevant.
 */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mach/machine.h>

#include <CoreFoundation/CoreFoundation.h>

#include "hostarch.h"

#define FAT_MAGIC	0xcafebabeu
#define FAT_MAGIC_64	0xcafebabfu
#define MH_MAGIC	0xfeedfaceu
#define MH_MAGIC_64	0xfeedfacfu

#define MAX_ARCHS	64

/* The Installer always lists arm64 ahead of x86_64, no matter which
 * order the architectures appear in the Mach-O header. */
static const char *const arch_order[] = {
	"arm64", "x86_64", "i386", "arm"
};

static uint32_t
be32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	    ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t
le32(const unsigned char *p)
{
	return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
	    ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

/* The Installer's name for a Mach-O CPU type, or NULL when unknown. */
static const char *
arch_name(uint32_t cputype)
{
	switch (cputype) {
	case CPU_TYPE_X86 | CPU_ARCH_ABI64:	return "x86_64";
	case CPU_TYPE_ARM | CPU_ARCH_ABI64:	return "arm64";
	case CPU_TYPE_X86:			return "i386";
	case CPU_TYPE_ARM:			return "arm";
	default:				return NULL;
	}
}
/*
 * Collect the CPU types of a Mach-O file into cpus[].  Handles both a
 * universal ("fat") binary and a thin one.  Returns 0 on success.
 */
static int
macho_cputypes(const char *path, uint32_t *cpus, int max, int *out_n)
{
	FILE *f = fopen(path, "rb");
	if (f == NULL)
		return -1;

	unsigned char head[8];
	if (fread(head, 1, sizeof head, f) != sizeof head) {
		fclose(f);
		return -1;
	}

	int n = 0;
	uint32_t magic = be32(head);
	if (magic == FAT_MAGIC || magic == FAT_MAGIC_64) {
		int rec = (magic == FAT_MAGIC) ? 20 : 32;
		uint32_t count = be32(head + 4);
		if (count > MAX_ARCHS)
			count = MAX_ARCHS;
		unsigned char *recs = malloc((size_t)count * (size_t)rec + 1);
		if (recs == NULL) {
			fclose(f);
			return -1;
		}
		fseek(f, 8, SEEK_SET);
		size_t got = fread(recs, 1, (size_t)count * (size_t)rec, f);
		fclose(f);
		count = (uint32_t)(got / (size_t)rec);
		for (uint32_t i = 0; i < count; i++) {
			if (n < max)
				cpus[n++] = be32(recs + (size_t)i * (size_t)rec);
		}
		free(recs);
	} else {
		fclose(f);
		if (le32(head) != MH_MAGIC && le32(head) != MH_MAGIC_64)
			return -1;
		if (max > 0)
			cpus[n++] = le32(head + 4);
	}
	*out_n = n;
	return 0;
}

/* Path of a bundle's main executable, or NULL when it has none. */
static char *
bundle_executable_path(const char *bundle_path)
{
	CFStringRef cpath = CFStringCreateWithCString(NULL, bundle_path,
	    kCFStringEncodingUTF8);
	if (cpath == NULL)
		return NULL;
	CFURLRef url = CFURLCreateWithFileSystemPath(NULL, cpath,
	    kCFURLPOSIXPathStyle, false);
	CFRelease(cpath);
	if (url == NULL)
		return NULL;

	CFBundleRef bundle = CFBundleCreate(NULL, url);
	CFRelease(url);
	if (bundle == NULL)
		return NULL;
	CFURLRef exe = CFBundleCopyExecutableURL(bundle);
	CFRelease(bundle);
	if (exe == NULL)
		return NULL;

	char buf[PATH_MAX];
	Boolean ok = CFURLGetFileSystemRepresentation(exe, true, (UInt8 *)buf,
	    (CFIndex)sizeof buf);
	CFRelease(exe);
	if (!ok)
		return NULL;
	return strdup(buf);
}

/* Is name already present as a whole field of the comma-separated list? */
static int
arch_listed(const char *list, const char *name)
{
	size_t len = strlen(name);
	for (const char *p = list; p != NULL && *p != '\0'; ) {
		const char *end = strchr(p, ',');
		size_t field = end ? (size_t)(end - p) : strlen(p);
		if (field == len && memcmp(p, name, len) == 0)
			return 1;
		p = end ? end + 1 : NULL;
	}
	return 0;
}

char *
host_archs_for_bundle(const char *bundle_path)
{
	if (bundle_path == NULL || *bundle_path == '\0')
		return NULL;

	char *exe = bundle_executable_path(bundle_path);
	if (exe == NULL)
		return NULL;

	uint32_t cpus[MAX_ARCHS];
	int n = 0;
	int rc = macho_cputypes(exe, cpus, MAX_ARCHS, &n);
	free(exe);
	if (rc != 0 || n == 0)
		return NULL;

	char out[128];
	size_t used = 0;
	out[0] = '\0';
	for (size_t o = 0; o < sizeof arch_order / sizeof arch_order[0]; o++) {
		for (int i = 0; i < n; i++) {
			const char *name = arch_name(cpus[i]);
			if (name == NULL || strcmp(name, arch_order[o]) != 0)
				continue;
			if (arch_listed(out, name))
				continue;	/* already listed */
			size_t len = strlen(name);
			if (used + len + 2 >= sizeof out)
				break;
			if (used > 0)
				out[used++] = ',';
			memcpy(out + used, name, len);
			used += len;
			out[used] = '\0';
		}
	}
	if (used == 0)
		return NULL;
	return strdup(out);
}
