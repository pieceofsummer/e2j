#!/usr/bin/env python3

import struct

# https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html

class CONSTANT_Utf8:
    def __init__(self, value):
        self.value = value
        
    def __repr__(self):
        return self.value
        
    @classmethod
    def read(self, data, offset, consts):
        length, = struct.unpack_from('>H', data, offset)
        value = data[offset+2:offset+2+length].decode()
        return self(value), offset + 2 + length
    
class CONSTANT_Integer:
    def __init__(self, value):
        self.value = value
        
    def __repr__(self):
        return str(self.value)
    
    @classmethod
    def read(self, data, offset, consts):
        value, = struct.unpack_from('>i', data, offset)
        return self(value), offset + 4
    
class CONSTANT_Float:
    def __init__(self, value):
        self.value = value
        
    def __repr__(self):
        return str(self.value)
    
    @classmethod
    def read(self, data, offset, consts):
        value, = struct.unpack_from('>f', data, offset)
        return self(value), offset + 4
    
class CONSTANT_Long:
    def __init__(self, value):
        self.value = value
        
    def __repr__(self):
        return str(self.value)
    
    @classmethod
    def read(self, data, offset, consts):
        value, = struct.unpack_from('>q', data, offset)
        return self(value), offset + 8
    
class CONSTANT_Double:
    def __init__(self, value):
        self.value = value
        
    def __repr__(self):
        return str(self.value)
    
    @classmethod
    def read(self, data, offset, consts):
        value, = struct.unpack_from('>d', data, offset)
        return self(value), offset + 8

class CONSTANT_String:
    def __init__(self, pool, string_index):
        self.pool = pool
        self.string_index = string_index
        
    @property
    def value(self):
        return self.pool[self.string_index]
        
    def __repr__(self):
        return self.value
    
    @classmethod
    def read(self, data, offset, consts):
        string_index, = struct.unpack_from('>H', data, offset)
        return self(consts, string_index), offset + 2
    
class CONSTANT_Class:
    def __init__(self, pool, name_index):
        self.pool = pool
        self.name_index = name_index
        
    @property
    def name(self):
        return self.pool[self.name_index]
        
    def __repr__(self):
        return f'Class {self.name}'
    
    @classmethod
    def read(self, data, offset, consts):
        name_index, = struct.unpack_from('>H', data, offset)
        return self(consts, name_index), offset + 2

class CONSTANT_NameAndType:
    def __init__(self, pool, name_index, descriptor_index):
        self.pool = pool
        self.name_index = name_index
        self.descriptor_index = descriptor_index
        
    @property
    def name(self):
        return self.pool[self.name_index]
    
    @property
    def descriptor(self):
        return self.pool[self.descriptor_index]
    
    def __repr__(self):
        return f'NameAndType {self.name}:{self.descriptor}'
    
    @classmethod
    def read(self, data, offset, consts):
        name_index, descriptor_index = struct.unpack_from('>HH', data, offset)
        return self(consts, name_index, descriptor_index), offset + 4

class CONSTANT_XXXref:
    def __init__(self, pool, class_index, name_and_type_index):
        self.pool = pool
        self.class_index = class_index
        self.name_and_type_index = name_and_type_index
        
    @property
    def clazz(self):
        return self.pool[self.class_index]
    
    @property
    def name_and_type(self):
        return self.pool[self.name_and_type_index]
    
    @classmethod
    def read(self, data, offset, consts):
        class_index, name_and_type_index = struct.unpack_from('>HH', data, offset)
        return self(consts, class_index, name_and_type_index), offset + 4

class CONSTANT_Fieldref(CONSTANT_XXXref):
    def __repr__(self):
        return f'FieldRef {self.clazz.name}.{self.name_and_type.name}:{self.name_and_type.descriptor}'

class CONSTANT_Methodref(CONSTANT_XXXref):
    def __repr__(self):
        return f'MethodRef {self.clazz.name}.{self.name_and_type.name}:{self.name_and_type.descriptor}'
    
class CONSTANT_InterfaceMethodref(CONSTANT_XXXref):
    def __repr__(self):
        return f'InterfaceMethodRef {self.clazz.name}.{self.name_and_type.name}:{self.name_and_type.descriptor}'
    
class CONSTANT_MethodHandle:
    def __init__(self, pool, reference_kind, reference_index):
        self.pool = pool
        self.reference_kind = reference_kind
        self.reference_index = reference_index
        
    @property
    def reference(self):
        return self.pool[self.reference_index]
        
    def __repr__(self):
        return f'MethodHandle {self.reference}'

    @classmethod
    def read(self, data, offset, consts):
        reference_kind, reference_index = struct.unpack_from('>BH', data, offset)
        return self(consts, reference_kind, reference_index), offset + 3
    
class CONSTANT_MethodType:
    def __init__(self, pool, descriptor_index):
        self.pool = pool
        self.descriptor_index = descriptor_index
        
    @property
    def descriptor(self):
        return self.pool[self.descriptor_index]
        
    def __repr__(self):
        return f'MethodType {self.descriptor}'
    
    @classmethod
    def read(self, data, offset, consts):
        descriptor_index, = struct.unpack_from('>H', data, offset)
        return self(consts, descriptor_index), offset + 2
    
class CONSTANT_InvokeDynamic:
    def __init__(self, pool, bootstrap_method_attr_index, name_and_type_index):
        self.pool = pool
        self.bootstrap_method_attr_index = bootstrap_method_attr_index
        self.name_and_type_index = name_and_type_index
    
    @property
    def name_and_type(self):
        return self.pool[self.name_and_type_index]

    def __repr__(self):
        return f'InvokeDynamic {self.bootstrap_method_attr_index} -> {self.name_and_type}'
    
    @classmethod
    def read(self, data, offset, consts):
        bootstrap_method_attr_index, name_and_type_index = struct.unpack_from('>HH', data, offset)
        return self(consts, bootstrap_method_attr_index, name_and_type_index), offset + 4

CONSTANTS = {
    1: CONSTANT_Utf8,
    3: CONSTANT_Integer,
    4: CONSTANT_Float,
    5: CONSTANT_Long,
    6: CONSTANT_Double,
    7: CONSTANT_Class,
    8: CONSTANT_String,
    9: CONSTANT_Fieldref,
    10: CONSTANT_Methodref,
    11: CONSTANT_InterfaceMethodref,
    12: CONSTANT_NameAndType,
    15: CONSTANT_MethodHandle,
    16: CONSTANT_MethodType,
    18: CONSTANT_InvokeDynamic
}
    
def parse_class(data):
    magic, ver_minor, ver_major, num_consts = struct.unpack_from('>IHHH', data)
    assert magic == 0xcafebabe, f'Invalid class: {magic:x}'
    
    consts = [None] * num_consts
    
    offset = 10
    for i in range(1, num_consts):
        consts[i], offset = CONSTANTS[data[offset]].read(data, offset + 1, consts)
    
    access_flags, this_class, super_class = struct.unpack_from('>HHH', data, offset)
    
    strings = [s.value.value for s in consts if isinstance(s, CONSTANT_String) and s.value.value]
    
    class_name = consts[this_class].name.value
    return class_name, strings

def hash_code(name):
    hash = 0
    for c in name:
        hash = (hash * 0x1f + ord(c)) & 0xffffffff
    return hash
