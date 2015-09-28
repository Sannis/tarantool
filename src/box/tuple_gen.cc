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

#include "third_party/tuple-cmp/tuple_compare_macro.h"

/** comparator special for NUM key with fieldno == 0 */
int
tuple_compare_n_first(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *)
{
	const char *a = tuple_a->data;
	const char *b = tuple_b->data;
	mp_decode_array(&a);
	mp_decode_array(&b);
	return mp_compare_uint(a, b);
}

/** comparator special for STR key with fieldno == 0 */
int
tuple_compare_s_first(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *)
{
	int r;
	const char *field_a = tuple_a->data;
	const char *field_b = tuple_b->data;
	mp_decode_array(&field_a);
	mp_decode_array(&field_b);
	uint32_t size_a = mp_decode_strl(&field_a);
	uint32_t size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

const tuple_cmp_t tuple_compare_arr_first[2] = {
	tuple_compare_n_first,
	tuple_compare_s_first
};

tuple_cmp_t
tuple_gen_compare(const struct key_def *def) {
	if (def->part_count > 3)
		return tuple_compare;
	uint32_t cmp_id = 0;
	for (uint32_t i = 0; i < def->part_count; i++)
		cmp_id |= (def->parts[i].type == STRING) << i;

	if (def->part_count == 1 && def->parts[0].fieldno == 0)
		return tuple_compare_arr_first[cmp_id];

	return tuple_compare_arr[def->part_count][cmp_id];
}

tuple_cmp_wk_t
tuple_gen_compare_with_key(const struct key_def *def) {
	if (def->part_count > 3)
		return tuple_compare_with_key;
	uint32_t cmp_id = 0;
	for (uint32_t i = 0; i < def->part_count; i++)
		cmp_id |= (def->parts[i].type == STRING) << i;
	return tuple_compare_with_key_arr[cmp_id];
}
