/*
 * analyze - PackageInfo XML construction.
 *
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include "analyze.h"

/*
 * Reproduce Apple's generator-version attribute.  InstallCmds embeds its
 * marketing version ("864.12") and the running OS build (from
 * kern.osversion, e.g. "25F84"), yielding "InstallCmds-864.12 (25F84)".
 */
static void
generator_version(char *buf, size_t n)
{
	static const char ident[] = "productbuild-864.12";
	const char *dash = strrchr(ident, '-');
	double v = dash ? strtod(dash + 1, NULL) : 0.0;
	char osver[64] = "";
	size_t len = sizeof osver;
	if (sysctlbyname("kern.osversion", osver, &len, NULL, 0) != 0)
		osver[0] = '\0';
	snprintf(buf, n, "InstallCmds-%g (%s)", v, osver);
}

static int
aprintf(char **out, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int r = vasprintf(out, fmt, ap);
	va_end(ap);
	return r;
}

/*
 * Scan scripts_dir for "preinstall" and/or "postinstall" files.
 * Appends a <scripts>...</scripts> block to *scripts_xml (malloc'd,
 * caller frees) on success, or leaves it NULL if neither is found.
 * Returns 0 on success, -1 on error.
 */
static int
collect_scripts(const char *scripts_dir, char **scripts_xml)
{
	if (scripts_dir == NULL) {
		*scripts_xml = NULL;
		return 0;
	}

	struct stat st;
	if (stat(scripts_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
		*scripts_xml = NULL;
		return 0;
	}

	char path[PATH_MAX];
	int has_pre = 0, has_post = 0;

	if (snprintf(path, sizeof path, "%s/preinstall", scripts_dir) < (int)sizeof path &&
	    stat(path, &st) == 0 && S_ISREG(st.st_mode))
		has_pre = 1;

	if (snprintf(path, sizeof path, "%s/postinstall", scripts_dir) < (int)sizeof path &&
	    stat(path, &st) == 0 && S_ISREG(st.st_mode))
		has_post = 1;

	if (!has_pre && !has_post) {
		*scripts_xml = NULL;
		return 0;
	}

	char *buf = NULL;
	if (aprintf(&buf, "    <scripts>\n") < 0 || buf == NULL)
		return -1;

	if (has_pre) {
		char *tmp = NULL;
		if (aprintf(&tmp, "%s        <preinstall file=\"./preinstall\" timeout=\"600\"/>\n",
		    buf) < 0 || tmp == NULL) {
			free(buf);
			return -1;
		}
		free(buf);
		buf = tmp;
	}
	if (has_post) {
		char *tmp = NULL;
		if (aprintf(&tmp, "%s        <postinstall file=\"./postinstall\" timeout=\"600\"/>\n",
		    buf) < 0 || tmp == NULL) {
			free(buf);
			return -1;
		}
		free(buf);
		buf = tmp;
	}

	char *tmp = NULL;
	if (aprintf(&tmp, "%s    </scripts>\n", buf) < 0 || tmp == NULL) {
		free(buf);
		return -1;
	}
	free(buf);
	*scripts_xml = tmp;
	return 0;
}

char *
pkginfo_build(const char *identifier, const char *version,
    const char *install_location, int content_mode, const char *scripts_dir,
    int number_of_files, size_t install_kbytes, size_t *out_len)
{
	char gen[128];
	generator_version(gen, sizeof gen);

	/* --content packages announce themselves as in-app content and carry
	 * no install location; otherwise a non-NULL install location becomes
	 * the install-location attribute. */
	char loc_attr[512];
	if (content_mode)
		snprintf(loc_attr, sizeof loc_attr,
		    " content-type=\"in-app\"");
	else if (install_location != NULL)
		snprintf(loc_attr, sizeof loc_attr,
		    " install-location=\"%s\"", install_location);
	else
		loc_attr[0] = '\0';

	char *head = NULL;
	if (aprintf(&head,
	    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
	    "<pkg-info overwrite-permissions=\"true\" relocatable=\"false\" "
	    "identifier=\"%s\" postinstall-action=\"none\" version=\"%s\" "
	    "format-version=\"2\" generator-version=\"%s\"%s auth=\"root\">\n"
	    "    <payload numberOfFiles=\"%d\" installKBytes=\"%zu\"/>\n",
	    identifier ? identifier : "com.apple.unknown",
	    version ? version : "0",
	    gen, loc_attr,
	    number_of_files > 0 ? number_of_files : 1,
	    install_kbytes) < 0 || head == NULL)
		return NULL;

	char *scripts_xml = NULL;
	if (collect_scripts(scripts_dir, &scripts_xml) != 0) {
		free(head);
		return NULL;
	}

	char *tail = NULL;
	if (aprintf(&tail,
	    "    <bundle-version/>\n"
	    "    <upgrade-bundle/>\n"
	    "    <update-bundle/>\n"
	    "    <atomic-update-bundle/>\n"
	    "    <strict-identifier/>\n"
	    "    <relocate/>\n"
	    "%s"
	    "</pkg-info>", scripts_xml ? scripts_xml : "") < 0 || tail == NULL) {
		free(head);
		free(scripts_xml);
		return NULL;
	}
	free(scripts_xml);

	size_t hl = strlen(head);
	size_t tl = strlen(tail);
	char *both = malloc(hl + tl + 1);
	if (both == NULL) {
		free(head);
		free(tail);
		return NULL;
	}
	memcpy(both, head, hl);
	memcpy(both + hl, tail, tl + 1);
	free(head);
	free(tail);

	*out_len = hl + tl;
	return both;
}
