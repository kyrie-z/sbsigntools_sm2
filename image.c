/*
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <ccan/talloc/talloc.h>
#include <openssl/sha.h>

#include "image.h"

#define DATA_DIR_CERT_TABLE	4

struct image *image_load(const char *filename)
{
	unsigned int bytes_read;
	struct stat statbuf;
	struct image *image;
	int rc;

	image = talloc(NULL, struct image);
	if (!image) {
		perror("talloc(image)");
		return NULL;
	}

	image->fd = open(filename, O_RDONLY);
	if (image->fd < 0) {
		perror("open");
		goto err;
	}

	rc = fstat(image->fd, &statbuf);
	if (rc) {
		perror("fstat");
		goto err;
	}

	image->size = statbuf.st_size;

	image->buf = talloc_size(image, image->size);
	if (!image->buf) {
		perror("talloc(buf)");
		goto err;
	}

	for (bytes_read = 0; bytes_read < image->size; bytes_read += rc) {
		rc = read(image->fd, image->buf + bytes_read,
					image->size - bytes_read);
		if (rc < 0) {
			perror("read");
			break;
		}
		if (rc == 0)
			break;
	}

	if (bytes_read < image->size) {
		fprintf(stderr, "error reading input file\n");
		goto err;
	}

	lseek(image->fd, 0, SEEK_SET);
	return image;
err:
	talloc_free(image);
	return NULL;
}

int image_pecoff_parse(struct image *image)
{
	char nt_sig[] = {'P', 'E', 0, 0};
	size_t size = image->size;
	uint32_t addr;

	/* sanity checks */
	if (size < sizeof(*image->doshdr)) {
		fprintf(stderr, "file is too small for DOS header\n");
		return -1;
	}

	image->doshdr = image->buf;

	if (image->doshdr->e_magic[0] != 0x4d
			|| image->doshdr->e_magic[1] != 0x5a) {
		fprintf(stderr, "Invalid DOS header magic\n");
		return -1;
	}

	addr = *(uint32_t *)image->doshdr->e_lfanew;
	if (addr >= image->size) {
		fprintf(stderr, "pehdr is beyond end of file [0x%08x]\n",
				addr);
		return -1;
	}

	if (addr + sizeof(*image->pehdr) > image->size) {
		fprintf(stderr, "File not large enough to contain pehdr\n");
		return -1;
	}

	image->pehdr = image->buf + addr;
	if (memcmp(image->pehdr->nt_signature, nt_sig, sizeof(nt_sig))) {
		fprintf(stderr, "Invalid PE header signature\n");
		return -1;
	}

	if (*(uint16_t *)image->pehdr->f_magic != AMD64MAGIC) {
		fprintf(stderr, "Invalid PE header magic for x86_64\n");
		return -1;
	}

	if (*(uint16_t *)image->pehdr->f_opthdr != sizeof(*image->aouthdr)) {
		fprintf(stderr, "Invalid a.out header size\n");
		return -1;
	}

	if (image->size < sizeof(*image->doshdr) + sizeof(*image->pehdr)
			+ sizeof(*image->aouthdr)) {
		fprintf(stderr, "file is too small for a.out header\n");
		return -1;
	}

	/* a.out header directly follows PE header */
	image->aouthdr = (void *)(image->pehdr+1);

	if (image->aouthdr->standard.magic[0] != 0x0b ||
			image->aouthdr->standard.magic[1] != 0x02) {
		fprintf(stderr, "Invalid a.out machine type\n");
		return -1;
	}

	image->data_dir = (void *)image->aouthdr->DataDirectory;
	image->data_dir_sigtable = &image->data_dir[DATA_DIR_CERT_TABLE];
	image->checksum = (uint32_t *)image->aouthdr->CheckSum;

	image->cert_table_size = image->data_dir_sigtable->size;
	if (image->cert_table_size)
		image->cert_table = image->buf + image->data_dir_sigtable->addr;
	else
		image->cert_table = NULL;

	image->sections = *(uint16_t *)image->pehdr->f_nscns;
	image->scnhdr = (void *)(image->aouthdr+1);

	return 0;
}

static int align_up(int size, int align)
{
	return (size + align - 1) & ~(align - 1);
}

static int cmp_regions(const void *p1, const void *p2)
{
	const struct region *r1 = p1, *r2 = p2;

	if (r1->data < r2->data)
		return -1;
	if (r1->data > r2->data)
		return 1;
	return 0;
}

static void set_region_from_range(struct region *region, void *start, void *end)
{
	region->data = start;
	region->size = end - start;
}

int image_find_regions(struct image *image)
{
	struct region *regions;
	int i, gap_warn;
	uint32_t align;
	size_t bytes;

	gap_warn = 0;
	align = *(uint32_t *)image->aouthdr->FileAlignment;

	/* now we know where the checksum and cert table data is, we can
	 * construct regions that need to be signed */
	bytes = 0;
	image->n_checksum_regions = 0;
	image->checksum_regions = NULL;

	image->n_checksum_regions = 3;
	image->checksum_regions = talloc_zero_array(image,
					struct region,
					image->n_checksum_regions);

	/* first region: beginning to checksum field */
	regions = image->checksum_regions;
	set_region_from_range(&regions[0], image->buf, image->checksum);
	regions[0].name = "begin->cksum";
	bytes += regions[0].size;

	bytes += sizeof(*image->checksum);

	/* second region: end of checksum to certificate table entry */
	set_region_from_range(&regions[1],
			image->checksum + 1,
			image->data_dir_sigtable
			);
	regions[1].name = "cksum->datadir[CERT]";
	bytes += regions[1].size;

	bytes += sizeof(struct data_dir_entry);
	/* third region: end of checksum to end of headers */
	set_region_from_range(&regions[2],
				(void *)image->data_dir_sigtable
					+ sizeof(struct data_dir_entry),
				image->buf +
				*(uint32_t *)image->aouthdr->SizeOfHeaders);
	regions[2].name = "datadir[CERT]->headers";
	bytes += regions[2].size;

	/* add COFF sections */
	for (i = 0; i < image->sections; i++) {
		uint32_t file_offset, file_size;

		file_offset = *(uint32_t *)image->scnhdr[i].s_scnptr;
		file_size = *(uint32_t *)image->scnhdr[i].s_size;

		if (!file_size)
			continue;

		image->n_checksum_regions++;
		image->checksum_regions = talloc_realloc(image,
				image->checksum_regions,
				struct region,
				image->n_checksum_regions);
		regions = image->checksum_regions;

		regions[i + 3].data = image->buf + file_offset;
		regions[i + 3].size = align_up(file_size, align);
		regions[i + 3].name = talloc_strndup(image->checksum_regions,
					image->scnhdr[i].s_name, 8);
		bytes += regions[i + 3].size;

		if (regions[i+2].data + regions[i+2].size
				!= regions[i+3].data) {
			fprintf(stderr, "warning: gap in section table between "
					"%s and %s\n",
					regions[i+2].name, regions[i+3].name);
			gap_warn = 1;
		}
	}

	if (gap_warn)
		fprintf(stderr, "gaps in the section table may result in "
				"different checksums\n");

	if (bytes != image->size) {
		fprintf(stderr, "warning: data remaining[%zd vs %zd]: gaps "
				"between PE/COFF sections?\n",
				bytes, image->size);
	}

	qsort(image->checksum_regions, image->n_checksum_regions,
			sizeof(struct region), cmp_regions);

	return 0;
}

int image_hash_sha256(struct image *image, uint8_t digest[])
{
	struct region *region;
	SHA256_CTX ctx;
	int rc, i, n;

	rc = SHA256_Init(&ctx);
	if (!rc)
		return -1;

	n = 0;

	for (i = 0; i < image->n_checksum_regions; i++) {
		region = &image->checksum_regions[i];
		n += region->size;
#if 0
		printf("sum region: 0x%04lx -> 0x%04lx [0x%04x bytes]\n",
				region->data - image->buf,
				region->data - image->buf - 1 + region->size,
				region->size);

#endif
		rc = SHA256_Update(&ctx, region->data, region->size);
		if (!rc)
			return -1;
	}

	rc = SHA256_Final(digest, &ctx);

	return !rc;
}

static int write_buf(int fd, void *buf, int size)
{
	int bytes_written, rc;

	for (bytes_written = 0; bytes_written < size;) {
		rc = write(fd, buf + bytes_written, size - bytes_written);

		if (rc <= 0) {
			perror("write");
			return -1;
		}
		bytes_written += rc;
	}

	return 0;
}

int image_write_signed(struct image *image, const char *filename)
{
	struct cert_table_header cert_table_header;
	int fd, rc, len, padlen;
	uint8_t pad[8];

	cert_table_header.size = image->sigsize;
	cert_table_header.revision = 0x0200; /* = revision 2 */
	cert_table_header.type = 0x0002; /* PKCS signedData */

	len = sizeof(cert_table_header) + image->sigsize;

	/* pad to sizeof(pad)-byte boundary */
	padlen = align_up(len, sizeof(pad)) - len;

	/* update the image to contain signature data */
	image->data_dir_sigtable->addr = image->size;
	image->data_dir_sigtable->size = len + padlen;

	fd = open(filename, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	rc = write_buf(fd, image->buf, image->size);
	if (rc)
		goto out;

	rc = write_buf(fd, &cert_table_header, sizeof(cert_table_header));
	if (rc)
		goto out;

	rc = write_buf(fd, image->sigbuf, image->sigsize);
	if (rc)
		goto out;

	if (padlen) {
		memset(pad, 0, sizeof(pad));
		rc = write_buf(fd, pad, padlen);
	}

out:
	close(fd);
	return rc;
}