/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2024 Matti Finder
 * (written by Matti Finder <matti.finder@gmail.com>)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __RPMC_H__
#define __RPMC_H__ 1

#include <stdint.h>
#include "flash.h" // for flashctx

int rpmc_write_root_key(struct flashrom_flashctx * flash, const char * const keyfile, const unsigned int counter_address);

int rpmc_update_hmac_key(struct flashrom_flashctx * flash, const char * const keyfile, const uint32_t key_data, const unsigned int counter_address);

int rpmc_increment_counter(struct flashrom_flashctx * flash, const char * const keyfile, const uint32_t key_data, const unsigned int counter_address, const uint32_t previous_value);

int rpmc_get_monotonic_counter(struct flashrom_flashctx * flash, const char * const keyfile, const uint32_t key_data, const unsigned int counter_address);

int rpmc_read_data(struct flashrom_flashctx *flash);


#endif /* !__RPMC_H__ */
