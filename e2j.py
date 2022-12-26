#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from java_util import parse_class, hash_code
import argparse, struct, re, hashlib, io, zipfile
import pefile, magic, mimetypes

def namehash(name):
    return '%x' % hash_code(name.replace('/', '\\'))

# Add more well-known filenames when needed
WELL_KNOWN_FILES = {
    namehash('META-INF/'): 'META-INF/',
    namehash('META-INF/MANIFEST.MF'): 'META-INF/MANIFEST.MF',
    namehash('META-INF/INDEX.LIST'): 'META-INF/INDEX.LIST',
    namehash('META-INF/CERT.SF'): 'META-INF/CERT.SF',
    namehash('META-INF/CERT.RSA'): 'META-INF/CERT.RSA',
}

IV = b'r1g2s3r4i5h6s7_8e9u0'

def rc4_ksa(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        yield S[(S[i] + S[j]) % 256]
        
def xor256_decrypt(key, data, rounds=4):
    data = bytearray(data)
    prng = rc4_ksa(key + IV[:16])
    prev = next(prng)
    for i, b in enumerate(data):
        tmp = [next(prng) for _ in range(rounds * 2)]
        for j in range(len(tmp) - 2, -1, -2):
            b = tmp[j] ^ (b - tmp[j + 1]) & 0xff
        data[i] = prev ^ b
        prev = b
    return data

def aes_decrypt(serial, hash, data):
    aes = AES.new(serial[:16].ljust(16, b'\0'), AES.MODE_CBC, hash.encode()[:8].ljust(8, b'\0') + IV[8:16])
    try:
        return unpad(aes.decrypt(data), aes.block_size)
    except ValueError:
        return data

def guess_extension(data):
    mime_type = magic.from_buffer(data, True)
    if mime_type:
        return mimetypes.guess_extension(mime_type)
    return None

def extract_j2e(input_path, output_path, verbose=False):
    with open(input_path, 'rb') as f:
        data = f.read()
        
    ZIP_MAGIC = b'PK\x03\x04'
    ROTATED_ZIP_MAGIC = b'\x14\xD2\xC0\x01'
        
    jar_pos = data.find(ZIP_MAGIC)
    if jar_pos == -1:
        raise Exception('Embedded jar not found')
    
    config_size, digest = struct.unpack_from('<I16s', data, jar_pos - 20)
    
    # start with plaintext jar at the end of binary
    jar = data[jar_pos:]
    
    # validate digest to make sure we found jar correctly
    md5 = hashlib.md5()
    md5.update(data[:jar_pos-16])
    md5.update(jar)
    if md5.digest() != digest:
        raise Exception("File digest doesn't match")
    
    config_pos = jar_pos - 20 - config_size
    config = data[config_pos:config_pos+config_size].rstrip(b'\0').decode('utf-8-sig').splitlines()
    
    # extract serial from config (it is used as decryption key)
    serial = next(line[7:] for line in config if line.startswith('serial ')).encode('ascii')
    
    if data[:2] == b'MZ':
        # Windows executable
        pe = pefile.PE(input_path)
        resource = [res for dir in pe.DIRECTORY_ENTRY_RESOURCE.entries if dir.id == 10 for res in dir.directory.entries if res.id == 128]
        if len(resource) > 0:
            # encrypted jar is stored in the resource
            resource = resource[0].directory.entries[0].data.struct
            jar = pe.get_data(resource.OffsetToData, resource.Size)
    else:
        # Mac/Linux executable
        jar_size, = struct.unpack_from('<I', data, config_pos - 4)
        if jar_size > 0:
            # encrypted jar goes right before config
            jar_pos = config_pos - 4 - jar_size
            jar = data[jar_pos:jar_pos+jar_size]
        
    # try decrypting jar itself if needed
    
    if jar[:4] == ROTATED_ZIP_MAGIC:
        # jar is encrypted by rotating bytes
        jar = bytes(map(lambda x: (x >> 6) | (x << 2) & 0xff, jar))
    elif jar[:4] != ZIP_MAGIC:
        # must be encrypted by xor256crypt
        jar = xor256_decrypt(serial, jar)
        if jar[:4] != ZIP_MAGIC:
            raise Exception('Failed to decrypt jar resource')
    
    # process jar to decrypt files and restore filenames
    
    hex_regex = re.compile(r'^[0-9a-f]+$', re.IGNORECASE)
    resource_name_regex = re.compile(r'^(?:\w+/)*\w+(\.\w+)?$')
    
    with io.BytesIO(jar) as f, zipfile.ZipFile(f, 'r') as zin, zipfile.ZipFile(output_path, 'w', zin.compression) as zout:
        unresolved = []
        path_strings = set()
        
        def add_path(path, include_self=True):
            path_parts = path.split('/')
            for n in range(1, len(path_parts)):
                path_strings.add('/'.join(path_parts[:n]) + '/')
            if include_self:
                path_strings.add(path)
        
        # first pass
        for file in zin.infolist():
            # skip j2e classes (they're added to unencrypted jar)
            if file.filename.startswith('com/regexlab/j2e/'):
                continue
            
            data = zin.read(file)
            
            if hex_regex.match(file.filename):
                # probably encrypted
                if len(data) > 0 and len(data) % 16 == 0:
                    data = aes_decrypt(serial, file.filename, data)
            
                if data.startswith(b'\xCA\xFE\xBA\xBE'):
                    # Java class file
                    class_name, class_strings = parse_class(data)
                    filename = class_name + '.class'
                    
                    # add class package path (for folder names)
                    add_path(class_name, False)
                    
                    # add some possible source file names
                    add_path(class_name + '.java')
                    add_path(class_name + '.form')
                    
                    # process strings in class for possible resource names
                    for s in class_strings:
                        # may be resource url, like:
                        #   jar:file.jar!/path/to/resource
                        #   classpath:/path/to/resource
                        s = s[max(s.rfind('!'), s.rfind(':'))+1:]
                            
                        if s.startswith('/'):
                            # looks like absolute path
                            if resource_name_regex.match(s[1:]):
                                add_path(s[1:])
                        else:
                            # could still be a relative path
                            if resource_name_regex.match(s):
                                add_path(f'{class_name}/{s}')
                        
                elif file.filename in WELL_KNOWN_FILES:
                    # some well-known filename
                    filename = WELL_KNOWN_FILES[file.filename]
                    
                elif data.startswith(b'Manifest-Version:'):
                    # Manifest file heuristic
                    filename = 'META-INF/MANIFEST.MF'
                    
                elif data.startswith(b'JarIndex-Version:'):
                    # Index file heuristic
                    filename = 'META-INF/INDEX.LIST'
                    
                else:
                    if not file.is_dir():
                        unresolved.append((file, data))
                    continue
                
                # do some processing of manifests content
                if filename == 'META-INF/MANIFEST.MF':
                    for paths in [line.split('Class-Path:')[1].strip().split() for line in data.decode('utf-8-sig').splitlines() if 'Class-Path:' in line]:
                        for path in paths:
                            if path not in ('.', './'):
                                add_path(path)
                    
                elif filename == 'META-INF/CERT.SF':
                    for path in [line.split('Name:')[1].strip() for line in data.decode('utf-8-sig').splitlines() if line.startswith('Name:')]:
                        add_path(path)
            else:
                # not encrypted
                filename = file.filename
            
            if verbose:
                print(f'Writing {file.filename} -> {filename}')
            
            file.filename = filename
            zout.writestr(file, data, file.compress_type)
        
        # calculate hashes for collected strings
        string_hashes = {}
        for path in path_strings:
            string_hashes[namehash(path)] = path
            
        # second pass
        for file, data in unresolved:
            filename = string_hashes.get(file.filename)
            if not filename:
                # file name still not resolved
                filename = f'UNRESOLVED/{file.filename}'
                
                # try guessing its type
                extension = guess_extension(data)
                if extension:
                    filename += extension
            
            if verbose:
                print(f'Writing {file.filename} -> {filename}')
            
            file.filename = filename
            zout.writestr(file, data, file.compress_type)
            
        if verbose:
            print('Done.')
            
parser = argparse.ArgumentParser(description=r'''
---------- Jar2Exe extraction tool ----------
          _         _                   _     
         /\ \     /\ \                 /\ \   
        /  \ \   /  \ \                \ \ \  
       / /\ \ \ / /\ \ \               /\ \_\ 
      / / /\ \_\\/_/\ \ \             / /\/_/ 
     / /_/_ \/_/    / / /    _       / / /    
    / /____/\      / / /    /\ \    / / /     
   / /\____\/     / / /  _  \ \_\  / / /      
  / / /______    / / /_/\_\ / / /_/ / /       
 / / /_______\  / /_____/ // / /__\/ /        
 \/__________/  \________/ \/_______/         
                                              
--- https://github.com/pieceofsummer/e2j/ ---
''', formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('input', type=str, help='input executable file')
parser.add_argument('output', type=str, help='output jar file')
parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')

args = parser.parse_args()

extract_j2e(args.input, args.output, args.verbose)