/**
 * @section LICENSE
 *
 * The MIT License
 *
 * @copyright Copyright (c) 2019 TileDB, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "hfile_internal.h"
#include <tiledb/tiledb.h>
#include <stdio.h>
#include <stdlib.h>

#define SCHEME "vfs"

typedef struct {
    hFILE base;
    tiledb_ctx_t* ctx;
    tiledb_vfs_t* vfs;
    tiledb_vfs_fh_t* vfs_fh;
    uint64_t offset;
    uint64_t size;
} hFILE_tiledb_vfs;

ssize_t tiledb_vfs_hfile_read(hFILE* fpv, void* buffer, size_t nbytes) {
  hFILE_tiledb_vfs* fp = (hFILE_tiledb_vfs*) fpv;

  if (nbytes+fp->offset > fp->size)
    nbytes = fp->size - fp->offset;

  tiledb_vfs_read(fp->ctx, fp->vfs_fh, fp->offset, buffer, nbytes);
  fp->offset += nbytes;
  return nbytes;
}

ssize_t tiledb_vfs_hfile_write(hFILE* fpv, const void* buffer, size_t nbytes) {
  hFILE_tiledb_vfs* fp = (hFILE_tiledb_vfs*) fpv;
  tiledb_vfs_write(fp->ctx, fp->vfs_fh, buffer, nbytes);
  return 0;
}

/*off_t tiledb_vfs_hfile_seek(hFILE* fpv, off_t offset, int whence) {
  hFILE_tiledb_vfs* fp = (hFILE_tiledb_vfs*) fpv;
  fp->offset = offset;
  return offset;
}*/

int tiledb_vfs_hfile_flush(hFILE* fpv) {
  hFILE_tiledb_vfs* fp = (hFILE_tiledb_vfs*) fpv;
  tiledb_vfs_sync(fp->ctx, fp->vfs_fh);
  return 0;
}

int tiledb_vfs_hfile_close(hFILE* fpv) {
  hFILE_tiledb_vfs* fp = (hFILE_tiledb_vfs*) fpv;
  tiledb_vfs_close(fp->ctx, fp->vfs_fh);
  tiledb_vfs_fh_free(&fp->vfs_fh);
  tiledb_vfs_free(&fp->vfs);
  tiledb_ctx_free(&fp->ctx);
  return 0;
}

static const struct hFILE_backend htslib_vfs_backend = {tiledb_vfs_hfile_read,
                                                        tiledb_vfs_hfile_write,
                                                        NULL,
                                                        tiledb_vfs_hfile_flush,
                                                        tiledb_vfs_hfile_close};

static hFILE *hopen_tiledb_vfs(const char *uri, const char *modestr)
{
  tiledb_vfs_mode_t mode = TILEDB_VFS_READ;
  if (strncmp(modestr, "r", 1) == 0)
    mode = TILEDB_VFS_READ;
  else if (strncmp(modestr, "w", 1) == 0)
    mode = TILEDB_VFS_WRITE;
  else if (strncmp(modestr, "a", 1) == 0)
    mode = TILEDB_VFS_WRITE;

  tiledb_config_t *config;
  tiledb_error_t* error = NULL;
  int rc = tiledb_config_alloc(&config, &error);
  if (rc != TILEDB_OK) {
    const char* msg;
    tiledb_error_message(error, &msg);
    fprintf(stderr, "%s\n", msg);
    return NULL;
  }

  tiledb_ctx_t *context;

  rc = tiledb_ctx_alloc(config, &context);
  tiledb_config_free(&config);

  if (rc != TILEDB_OK) {
    const char* msg;
    tiledb_error_message(error, &msg);
    fprintf(stderr, "%s\n", msg);
    return NULL;
  }


  hFILE_tiledb_vfs* fp =
      (hFILE_tiledb_vfs*) hfile_init(sizeof(hFILE_tiledb_vfs), modestr, 1024);
  if (fp == NULL)
    return NULL;

  fp->ctx = context;
  tiledb_vfs_alloc(context, NULL, &fp->vfs);
  // move the URI pointer pasted the first scheme and ://
  uri = uri + strlen(SCHEME) + 3;
  rc = tiledb_vfs_open(fp->ctx, fp->vfs, uri, mode, &fp->vfs_fh);
  if (rc != TILEDB_OK) {
    const char* msg;
    tiledb_error_message(error, &msg);
    fprintf(stderr, "%s\n", msg);
    return NULL;
  }

  rc = tiledb_vfs_file_size(fp->ctx, fp->vfs, uri, &fp->size);
  if (rc != TILEDB_OK) {
    const char* msg;
    tiledb_error_message(error, &msg);
    fprintf(stderr, "%s\n", msg);
    return NULL;
  }

  fp->base.backend = &htslib_vfs_backend;
  return &fp->base;
}

int hfile_plugin_init(struct hFILE_plugin *self)
{
  static const struct hFILE_scheme_handler handler =
      { hopen_tiledb_vfs, hfile_always_remote, "tiledb_vfs", 10 };

  self->name = "tiledb_vfs";
  hfile_add_scheme_handler(SCHEME, &handler);
  return 0;
}
