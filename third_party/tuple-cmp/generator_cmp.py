#!/usr/bin/env python
from sys import argv

def generate_cmp(cmp_type):
    print("/** comparator special for %s key */" % 
        ', '.join(['NUM' if c == 'n' else 'STR' for c in cmp_type]))
    print("int");
    print("tuple_compare_with_key_%s(const struct tuple *tuple, const char *key," % cmp_type)
    print("\t\t       uint32_t part_count, const struct key_def *key_def)")
    print("{")
    if (cmp_type.strip('n') != ''):
        print("\tuint32_t size_a, size_b;")
        print("\tconst char *key_field;")
    print("\tconst char *field;")
    print("\tassert(key != NULL);")
    print("\tassert(part_count <= key_def->part_count);")
    print("\tstruct tuple_format *format = tuple_format(tuple);")
    print("\tint r = 0; /* Part count can be 0 in wildcard searches. */")
    print("\tif (part_count == 0)")
    print("\t\treturn 0;")
    print("")
    for i, c in enumerate(cmp_type):
        print("\tfield = tuple_field_old(format, tuple, key_def->parts[%d].fieldno);" % i)
        if c == 'n':
            if i != len(cmp_type) - 1:
                print("\tif ((r = mp_compare_uint(field, key)) != 0 || part_count == %d)" % (i + 1))
                print("\t\treturn r;");
                print("\tmp_next(&key);")
                print("")
            else:
                print("\treturn mp_compare_uint(field, key);")
        elif c == 's':
            print("\tkey_field = key;")
            print("\tsize_a = mp_decode_strl(&field);")
            print("\tsize_b = mp_decode_strl(&key_field);")
            print("\tr = memcmp(field, key_field, MIN(size_a, size_b));")
            print("\tif (r == 0)")
            print("\t\tr = size_a < size_b ? -1 : size_a > size_b;")
            
            if i != len(cmp_type) - 1:
                print("\tif (r || part_count == %d)" % (i + 1))
                print("\t\treturn r;")
                print("\tmp_next(&key);")
                print("")        
            else:
                print("\treturn r;");            
        else:
            raise IOError("unexpected symbol %s" % c)
        
    print("}")
    
if __name__ == "__main__":
    generate_cmp(argv[1])