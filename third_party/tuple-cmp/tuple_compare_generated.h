/** comparator special for NUM, NUM, NUM key */
int
tuple_compare_with_key_nnn(const struct tuple *tuple, const char *key,
		       uint32_t part_count, const struct key_def *key_def)
{
	const char *field;
	assert(key != NULL);
	assert(part_count <= key_def->part_count);
	struct tuple_format *format = tuple_format(tuple);
	int r = 0; /* Part count can be 0 in wildcard searches. */
	if (part_count == 0)
		return 0;

	field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);
	if ((r = mp_compare_uint(field, key)) != 0 || part_count == 1)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[1].fieldno);
	if ((r = mp_compare_uint(field, key)) != 0 || part_count == 2)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[2].fieldno);
	return mp_compare_uint(field, key);
}

/** comparator special for STR, NUM, NUM key */
int
tuple_compare_with_key_snn(const struct tuple *tuple, const char *key,
		       uint32_t part_count, const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *key_field;
	const char *field;
	assert(key != NULL);
	assert(part_count <= key_def->part_count);
	struct tuple_format *format = tuple_format(tuple);
	int r = 0; /* Part count can be 0 in wildcard searches. */
	if (part_count == 0)
		return 0;

	field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r || part_count == 1)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[1].fieldno);
	if ((r = mp_compare_uint(field, key)) != 0 || part_count == 2)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[2].fieldno);
	return mp_compare_uint(field, key);
}

/** comparator special for NUM, STR, NUM key */
int
tuple_compare_with_key_nsn(const struct tuple *tuple, const char *key,
		       uint32_t part_count, const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *key_field;
	const char *field;
	assert(key != NULL);
	assert(part_count <= key_def->part_count);
	struct tuple_format *format = tuple_format(tuple);
	int r = 0; /* Part count can be 0 in wildcard searches. */
	if (part_count == 0)
		return 0;

	field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);
	if ((r = mp_compare_uint(field, key)) != 0 || part_count == 1)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[1].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r || part_count == 2)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[2].fieldno);
	return mp_compare_uint(field, key);
}

/** comparator special for STR, STR, NUM key */
int
tuple_compare_with_key_ssn(const struct tuple *tuple, const char *key,
		       uint32_t part_count, const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *key_field;
	const char *field;
	assert(key != NULL);
	assert(part_count <= key_def->part_count);
	struct tuple_format *format = tuple_format(tuple);
	int r = 0; /* Part count can be 0 in wildcard searches. */
	if (part_count == 0)
		return 0;

	field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r || part_count == 1)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[1].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r || part_count == 2)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[2].fieldno);
	return mp_compare_uint(field, key);
}

/** comparator special for NUM, NUM, STR key */
int
tuple_compare_with_key_nns(const struct tuple *tuple, const char *key,
		       uint32_t part_count, const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *key_field;
	const char *field;
	assert(key != NULL);
	assert(part_count <= key_def->part_count);
	struct tuple_format *format = tuple_format(tuple);
	int r = 0; /* Part count can be 0 in wildcard searches. */
	if (part_count == 0)
		return 0;

	field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);
	if ((r = mp_compare_uint(field, key)) != 0 || part_count == 1)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[1].fieldno);
	if ((r = mp_compare_uint(field, key)) != 0 || part_count == 2)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[2].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

/** comparator special for STR, NUM, STR key */
int
tuple_compare_with_key_sns(const struct tuple *tuple, const char *key,
		       uint32_t part_count, const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *key_field;
	const char *field;
	assert(key != NULL);
	assert(part_count <= key_def->part_count);
	struct tuple_format *format = tuple_format(tuple);
	int r = 0; /* Part count can be 0 in wildcard searches. */
	if (part_count == 0)
		return 0;

	field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r || part_count == 1)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[1].fieldno);
	if ((r = mp_compare_uint(field, key)) != 0 || part_count == 2)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[2].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

/** comparator special for NUM, STR, STR key */
int
tuple_compare_with_key_nss(const struct tuple *tuple, const char *key,
		       uint32_t part_count, const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *key_field;
	const char *field;
	assert(key != NULL);
	assert(part_count <= key_def->part_count);
	struct tuple_format *format = tuple_format(tuple);
	int r = 0; /* Part count can be 0 in wildcard searches. */
	if (part_count == 0)
		return 0;

	field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);
	if ((r = mp_compare_uint(field, key)) != 0 || part_count == 1)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[1].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r || part_count == 2)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[2].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

/** comparator special for STR, STR, STR key */
int
tuple_compare_with_key_sss(const struct tuple *tuple, const char *key,
		       uint32_t part_count, const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *key_field;
	const char *field;
	assert(key != NULL);
	assert(part_count <= key_def->part_count);
	struct tuple_format *format = tuple_format(tuple);
	int r = 0; /* Part count can be 0 in wildcard searches. */
	if (part_count == 0)
		return 0;

	field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r || part_count == 1)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[1].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r || part_count == 2)
		return r;
	mp_next(&key);

	field = tuple_field_old(format, tuple, key_def->parts[2].fieldno);
	key_field = key;
	size_a = mp_decode_strl(&field);
	size_b = mp_decode_strl(&key_field);
	r = memcmp(field, key_field, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

const tuple_cmp_wk_t tuple_compare_with_key_arr[8] = {
	tuple_compare_with_key_nnn,
	tuple_compare_with_key_snn,
	tuple_compare_with_key_nsn,
	tuple_compare_with_key_ssn,
	tuple_compare_with_key_nns,
	tuple_compare_with_key_sns,
	tuple_compare_with_key_nss,
	tuple_compare_with_key_sss,
};
