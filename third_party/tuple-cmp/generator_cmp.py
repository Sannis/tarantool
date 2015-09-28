#!/usr/bin/env python
from sys import argv
#TODO: fast cmp for 1 fld
def generate_cmp(cmp_type):
    print("/** comparator special for %s key */" % 
        ', '.join(['NUM' if c == 'n' else 'STR' for c in cmp_type]))
    print("int");
    print("tuple_compare_%s(const struct tuple *tuple_a, const struct tuple *tuple_b," % cmp_type)
    print("\t\t       const struct key_def *key_def)")
    print("{")
    if (cmp_type == ''):
        print("\t(void)tuple_a;")
        print("\t(void)tuple_b;")
        print("\t(void)key_def;")
        print("\treturn 0;")
        print("}")
        return
    if (cmp_type.strip('n') != ''):
        print("\tuint32_t size_a, size_b;")
        
    print("\tconst char *field_a, *field_b;")
    print("\tstruct tuple_format *format_a = tuple_format(tuple_a);")
    print("\tstruct tuple_format *format_b = tuple_format(tuple_b);")
    if (cmp_type != 'n'):
        print("\tint r;")
    print("")
    for i, c in enumerate(cmp_type):
        print("\tfield_a = tuple_field_old(format_a, tuple_a, key_def->parts[%d].fieldno);" % i)
        print("\tfield_b = tuple_field_old(format_b, tuple_b, key_def->parts[%d].fieldno);" % i)
        if c == 'n':
            if i != len(cmp_type) - 1:
                print("\tif ((r = mp_compare_uint(field_a, field_b)) != 0)")
                print("\t\treturn r;");
                print("")
            else:
                print("\treturn mp_compare_uint(field_a, field_b);")
        elif c == 's':
            print("\tsize_a = mp_decode_strl(&field_a);")
            print("\tsize_b = mp_decode_strl(&field_b);")
            print("\tr = memcmp(field_a, field_b, MIN(size_a, size_b));")
            print("\tif (r == 0)")
            print("\t\tr = size_a < size_b ? -1 : size_a > size_b;")
            
            if i != len(cmp_type) - 1:
                print("\tif (r)")
                print("\t\treturn r;")
                print("")        
            else:
                print("\treturn r;");            
        else:
            raise IOError("unexpected symbol %s" % c)
        
    print("}")
    
if __name__ == "__main__":
    generate_cmp(argv[1])