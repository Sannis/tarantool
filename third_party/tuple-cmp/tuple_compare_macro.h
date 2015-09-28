#include<stdio.h>

#define QUOTE(x) #x
#define TUPLE_COMPARE_WITH_KEY(fld) \
int \
tuple_compare_with_key_##fld(const struct tuple *tuple, const char *key,\
		       uint32_t part_count, const struct key_def *key_def)\
{\
\
	uint32_t size_a, size_b;\
	const char *key_field;\
	const char *field;\
	assert(key != NULL);\
	assert(part_count <= key_def->part_count);\
	struct tuple_format *format = tuple_format(tuple);\
	int r = 0; /* Part count can be 0 in wildcard searches. */\
	if (part_count == 0)\
		return 0;\
	if (QUOTE(fld)[0] == 'n') {\
		field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);\
		if ((r = mp_compare_uint(field, key)) != 0 || part_count == 1)\
			return r;\
		mp_next(&key);\
	} else {\
		field = tuple_field_old(format, tuple, key_def->parts[0].fieldno);\
		key_field = key;\
		size_a = mp_decode_strl(&field);\
		size_b = mp_decode_strl(&key_field);\
		r = memcmp(field, key_field, MIN(size_a, size_b));\
		if (r == 0)\
			r = size_a < size_b ? -1 : size_a > size_b;\
		if (r || part_count == 1)\
			return r;\
		mp_next(&key);\
	}\
	if (QUOTE(fld)[1] == 'n') {\
		field = tuple_field_old(format, tuple, key_def->parts[1].fieldno);\
		if ((r = mp_compare_uint(field, key)) != 0 || part_count == 2)\
			return r;\
		mp_next(&key);\
	} else {\
		field = tuple_field_old(format, tuple, key_def->parts[1].fieldno);\
		key_field = key;\
		size_a = mp_decode_strl(&field);\
		size_b = mp_decode_strl(&key_field);\
		r = memcmp(field, key_field, MIN(size_a, size_b));\
		if (r == 0)\
			r = size_a < size_b ? -1 : size_a > size_b;\
		if (r || part_count == 2)\
			return r;\
		mp_next(&key);\
	}\
\
	if (QUOTE(fld)[2] == 'n') {\
		field = tuple_field_old(format, tuple, key_def->parts[2].fieldno);\
		return mp_compare_uint(field, key);\
	}\
	field = tuple_field_old(format, tuple, key_def->parts[2].fieldno);\
	key_field = key;\
	size_a = mp_decode_strl(&field);\
	size_b = mp_decode_strl(&key_field);\
	r = memcmp(field, key_field, MIN(size_a, size_b));\
	if (r == 0)\
		r = size_a < size_b ? -1 : size_a > size_b;\
	return r;\
}

#define TUPLE_COMPARE_FIELD(fld, idx) \
if (QUOTE(fld)[idx + 1] == '\0') {\
	if (QUOTE(fld)[idx] == 'n') { \
		field_a = tuple_field_old(format_a, tuple_a, \
			key_def->parts[idx].fieldno);\
		field_b = tuple_field_old(format_b, tuple_b, \
			key_def->parts[idx].fieldno);\
		return mp_compare_uint(field_a, field_b);\
	} else { \
		field_a = tuple_field_old(format_a, tuple_a, \
			key_def->parts[idx].fieldno);\
		field_b = tuple_field_old(format_b, tuple_b, \
			key_def->parts[idx].fieldno);\
		size_a = mp_decode_strl(&field_a);\
		size_b = mp_decode_strl(&field_b);\
		r = memcmp(field_a, field_b, MIN(size_a, size_b));\
		if (r == 0)\
			r = size_a < size_b ? -1 : size_a > size_b;\
		return r;\
	}\
} else {\
	if (QUOTE(fld)[idx] == 'n') {\
		field_a = tuple_field_old(format_a, tuple_a, \
			key_def->parts[idx].fieldno);\
		field_b = tuple_field_old(format_b, tuple_b, \
			key_def->parts[idx].fieldno);\
		if ((r = mp_compare_uint(field_a, field_b)) != 0)\
			return r;\
	} else {\
		field_a = tuple_field_old(format_a, tuple_a, \
			key_def->parts[idx].fieldno);\
		field_b = tuple_field_old(format_b, tuple_b, \
			key_def->parts[idx].fieldno);\
		size_a = mp_decode_strl(&field_a);\
		size_b = mp_decode_strl(&field_b);\
		r = memcmp(field_a, field_b, MIN(size_a, size_b));\
		if (r == 0)\
			r = size_a < size_b ? -1 : size_a > size_b;\
		if (r)\
			return r;\
	}\
}

#define TUPLE_COMPARE(fld) \
int tuple_compare_##fld(const struct tuple *tuple_a, const struct tuple *tuple_b,\
		       const struct key_def *key_def)\
{\
	if (QUOTE(fld)[0] == '\0')\
		return 0;\
	uint32_t size_a, size_b;\
	const char *field_a, *field_b;\
	struct tuple_format *format_a = tuple_format(tuple_a);\
	struct tuple_format *format_b = tuple_format(tuple_b);\
	int r = 0;\
\
	TUPLE_COMPARE_FIELD(fld, 0)\
	TUPLE_COMPARE_FIELD(fld, 1)\
	TUPLE_COMPARE_FIELD(fld, 2)\
\
	return 0;\
}

TUPLE_COMPARE_WITH_KEY(nnn)
TUPLE_COMPARE_WITH_KEY(snn)
TUPLE_COMPARE_WITH_KEY(nsn)
TUPLE_COMPARE_WITH_KEY(ssn)
TUPLE_COMPARE_WITH_KEY(nns)
TUPLE_COMPARE_WITH_KEY(sns)
TUPLE_COMPARE_WITH_KEY(nss)
TUPLE_COMPARE_WITH_KEY(sss)

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

TUPLE_COMPARE()
TUPLE_COMPARE(n)
TUPLE_COMPARE(s)
TUPLE_COMPARE(nn)
TUPLE_COMPARE(sn)
TUPLE_COMPARE(ns)
TUPLE_COMPARE(ss)
TUPLE_COMPARE(nnn)
TUPLE_COMPARE(snn)
TUPLE_COMPARE(nsn)
TUPLE_COMPARE(ssn)
TUPLE_COMPARE(nns)
TUPLE_COMPARE(sns)
TUPLE_COMPARE(nss)
TUPLE_COMPARE(sss)

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
