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

/** comparator special for  key */
int
tuple_compare_(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	(void)tuple_a;
	(void)tuple_b;
	(void)key_def;
	return 0;
}

/** comparator special for NUM key */
int
tuple_compare_n(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	return mp_compare_uint(field_a, field_b);
}

/** comparator special for STR key */
int
tuple_compare_s(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

/** comparator special for NUM, NUM key */
int
tuple_compare_nn(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	if ((r = mp_compare_uint(field_a, field_b)) != 0)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	return mp_compare_uint(field_a, field_b);
}

/** comparator special for STR, NUM key */
int
tuple_compare_sn(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	return mp_compare_uint(field_a, field_b);
}

/** comparator special for NUM, STR key */
int
tuple_compare_ns(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	if ((r = mp_compare_uint(field_a, field_b)) != 0)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

/** comparator special for STR, STR key */
int
tuple_compare_ss(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

/** comparator special for NUM, NUM, NUM key */
int
tuple_compare_nnn(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	if ((r = mp_compare_uint(field_a, field_b)) != 0)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	if ((r = mp_compare_uint(field_a, field_b)) != 0)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[2].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[2].fieldno);
	return mp_compare_uint(field_a, field_b);
}

/** comparator special for STR, NUM, NUM key */
int
tuple_compare_snn(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	if ((r = mp_compare_uint(field_a, field_b)) != 0)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[2].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[2].fieldno);
	return mp_compare_uint(field_a, field_b);
}

/** comparator special for NUM, STR, NUM key */
int
tuple_compare_nsn(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	if ((r = mp_compare_uint(field_a, field_b)) != 0)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[2].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[2].fieldno);
	return mp_compare_uint(field_a, field_b);
}

/** comparator special for STR, STR, NUM key */
int
tuple_compare_ssn(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[2].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[2].fieldno);
	return mp_compare_uint(field_a, field_b);
}

/** comparator special for NUM, NUM, STR key */
int
tuple_compare_nns(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	if ((r = mp_compare_uint(field_a, field_b)) != 0)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	if ((r = mp_compare_uint(field_a, field_b)) != 0)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[2].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[2].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

/** comparator special for STR, NUM, STR key */
int
tuple_compare_sns(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	if ((r = mp_compare_uint(field_a, field_b)) != 0)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[2].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[2].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

/** comparator special for NUM, STR, STR key */
int
tuple_compare_nss(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	if ((r = mp_compare_uint(field_a, field_b)) != 0)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[2].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[2].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	return r;
}

/** comparator special for STR, STR, STR key */
int
tuple_compare_sss(const struct tuple *tuple_a, const struct tuple *tuple_b,
		       const struct key_def *key_def)
{
	uint32_t size_a, size_b;
	const char *field_a, *field_b;
	struct tuple_format *format_a = tuple_format(tuple_a);
	struct tuple_format *format_b = tuple_format(tuple_b);
	int r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[0].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[0].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[1].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[1].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
	if (r == 0)
		r = size_a < size_b ? -1 : size_a > size_b;
	if (r)
		return r;

	field_a = tuple_field_old(format_a, tuple_a, key_def->parts[2].fieldno);
	field_b = tuple_field_old(format_b, tuple_b, key_def->parts[2].fieldno);
	size_a = mp_decode_strl(&field_a);
	size_b = mp_decode_strl(&field_b);
	r = memcmp(field_a, field_b, MIN(size_a, size_b));
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
const tuple_cmp_t tuple_compare_arr[4][8] = {
	{
		tuple_compare_,
	},
	{
		tuple_compare_n,
		tuple_compare_s,
	},
	{
		tuple_compare_nn,
		tuple_compare_sn,
		tuple_compare_ns,
		tuple_compare_ss,
	},
	{
		tuple_compare_nnn,
		tuple_compare_snn,
		tuple_compare_nsn,
		tuple_compare_ssn,
		tuple_compare_nns,
		tuple_compare_sns,
		tuple_compare_nss,
		tuple_compare_sss,
	},
};
