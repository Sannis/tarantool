/*
 * Copyright 2010-2015, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "tuple_gen.h"

#include "tuple.h"

/** comparator special for NUM, STR key */
int
tuple_compare_with_key_ns(const struct tuple *tuple, const char *key,
		       uint32_t part_count, const struct key_def *key_def)
{
	(void)part_count;
	assert(key != NULL);
	assert(part_count <= key_def->part_count);
	struct tuple_format *format = tuple_format(tuple);

	int r = 0; /* Part count can be 0 in wildcard searches. */
	if (part_count == 0)
		return 0;
	const char *field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);
	if ((r = mp_compare_uint(field, key)) != 0 || part_count == 1)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[1].fieldno);
	uint32_t size_a = mp_decode_strl(&field);
	uint32_t size_b = mp_decode_strl(&key);
	const char *a = field;
	const char *b = key;
	r = memcmp(a, b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;

	return r;
}
/** comparator special for NUM key */
int
tuple_compare_with_key_n(const struct tuple *tuple, const char *key,
		       uint32_t part_count, const struct key_def *key_def)
{
	if (part_count == 0)
		return 0;
	struct tuple_format *format = tuple_format(tuple);
	const char *field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);
	return mp_compare_uint(field, key);
}
/** comparator special for STR key */
int
tuple_compare_with_key_s(const struct tuple *tuple, const char *key,
		       uint32_t part_count, const struct key_def *key_def)
{
	if (part_count == 0)
		return 0;
	struct tuple_format *format = tuple_format(tuple);
	const char *field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);
	uint32_t size_a = mp_decode_strl(&field);
	uint32_t size_b = mp_decode_strl(&key);
	const char *a = field;
	const char *b = key;
	int r = memcmp(a, b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

void *tuple_gen_compare(const struct key_def *def) {
	(void)def;
	return (void *)tuple_compare;
}

void *tuple_gen_compare_with_key(const struct key_def *def) {

	if (def->part_count <= 2 && def->parts[0].type == NUM &&
	    (def->part_count == 1 || def->parts[1].type == STRING)) {
		return (void *)tuple_compare_with_key_ns;
	}
	//if (def->part_count == 1 && def->parts[0].type == NUM)
	//
	//if (def->part_count == 1 && def->parts[0].type == STRING)
	//	return (void *)tuple_compare_with_key_s;

	return (void *)tuple_compare_with_key;
}
