#/usr/bin/python3
import os
import hashlib
from datetime import datetime
from shutil import move
import pickle

#os.chdir (os.path.join('/u00','share','giovanna','Pictures'))
#os.chdir('e:\\')
BLOCKSIZE = 65536*8
DRY_RUN = False
DEBUG = False

def format_bytes(size):
    # 2**10 = 1024
    power = 2**10
    n = 0
    power_labels = {0 : '', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power:
        size /= power
        n += 1
    return "{:.3f} {}".format(size, power_labels[n]+'bytes')

def find(name, path):
    files_dict = {}
    n_files=0
    total_files=0
    all_files = {}
    for root, dirs, files in os.walk(path):
        if (root.startswith('.dup') or root.startswith('_new') ):
            continue
        total_files += len(files)
        if (DEBUG):
            print ('Searching files: {}'.format(total_files), end='\r')
        all_files.update({ os.path.join(root,k):True for k in files})

        for name in files:
            fullpath= os.path.join(root, name)
            filesize= os.path.getsize(os.path.join(root, name))
            created=  os.path.getctime(os.path.join(root, name))
            modified= os.path.getmtime(os.path.join(root, name))

            if filesize not in files_dict:
                files_dict[filesize] = {}

            files_dict[filesize].update({fullpath: {
                'filepath': root,
                'filename': name,
                #'size': filesize,
                'created':  created,
                'modified': modified}
            })

    # Clean files to have only sizes with multiple sizes
    files_dict = { k:v for k,v in files_dict.items() if len(v)>1 and k>0}
    
    n_files = sum ( [ len(v) for k,v in files_dict.items() ] )
    print ("Found {}/{} candidate files to hash".format( n_files, total_files))
    
            
    # Hash files that have same sizes

    # Read hash cache and remove deleted files
    known_hashes = {}
    if (os.path.exists('.hash')):
        known_hashes = pickle.load(open (".hash", "rb"))
        known_hashes = { k:v for k,v in known_hashes.items() if k in all_files}

    all_files={}
    hashes= {}
    i = 0
    j = 0
    dirty_hash = False
    for size in sorted(files_dict.keys(),reverse=True):
        for file in files_dict[size]:
            i = i + 1
            all_files.update({ k:True for k in files})

            if (file in known_hashes):
                if (known_hashes[file]['created'] == files_dict[size][file]['created'] and
                    known_hashes[file]['modified'] == files_dict[size][file]['modified'] and
                    known_hashes[file]['size'] == size):

                    if (DEBUG):
                        print ('Already hashed file: {}/{}{}'.format(i, n_files,' '*80)[:79], end='\r')
                    hash = known_hashes[file]['hash']
                    if (hash not in hashes):
                        hashes[hash]={}
            
                    hashes[hash].update( {file: { **files_dict[size][file], 'filesize': size} })
                    continue
            dirty_hash=True
            if (DEBUG):
                print ('Hashing file: {}/{}{}'.format(i, n_files,' '*80)[:79], end='\r')
            hasher = hashlib.md5()
            with open (file,'rb') as f:
                buf = f.read(BLOCKSIZE)
                while (len(buf)>0):
                    hasher.update(buf)
                    buf = f.read(BLOCKSIZE)
                    j+= len(buf)
            hash = hasher.hexdigest()
            if (hash not in hashes):
                hashes[hash]={}
            hashes[hash].update( {file: { **files_dict[size][file], 'filesize': size} })
            if (file not in known_hashes):
                known_hashes[file]={}
            known_hashes[file].update({
                'created': files_dict[size][file]['created'],
                'modified':files_dict[size][file]['modified'],
                'size': size,
                'hash': hash
            })

            if (j>>30 > 0):
                with open(".hash", 'wb') as fh:
                    pickle.dump(known_hashes, fh)
                j=0
            
        
    files_dict={}
    if dirty_hash:
        with open(".hash", 'wb') as fh:
            pickle.dump(known_hashes, fh)

    hashes = { k:v for k,v in hashes.items() if len(v)>1}
    n_files = sum ( [ len(v) for k,v in hashes.items() ] )
    print ("Found {} duplicated files ".format( n_files ))

    return hashes


hashes = find (name='', path='.')
total_size = 0
destpaths = {}

for hash in hashes:
    print ('Arquivos de tamanho: {}, Hash: 0x{}'.format(
        format_bytes(hashes[hash][list(hashes[hash].keys())[0]]['filesize']),
        hash))
    for file in hashes[hash]:
        print (u'\t{}: Created {}, Modified {}'.format(
            file, 
            datetime.fromtimestamp(hashes[hash][file]['created']), 
            datetime.fromtimestamp(hashes[hash][file]['modified'])))
    to_remove = [ f for f in sorted (hashes[hash], key=lambda x: [
        len(os.path.split(hashes[hash][x]['filepath'])),
        -ord(os.path.split(hashes[hash][x]['filepath'])[-1][0]),
        len(hashes[hash][x]['filename']),
        len(os.path.split(hashes[hash][x]['filepath'])[0]),
        -len(hashes[hash][x]['filepath']), 
    ])][1:]
    print (u"\tRemoving {}:".format(format_bytes(len(to_remove) * hashes[hash][list(hashes[hash].keys())[0]]['filesize'])))
    total_size+=len(to_remove) * hashes[hash][list(hashes[hash].keys())[0]]['filesize']
    for file in to_remove:
        destpath = os.path.join('.dup', hashes[hash][file]['filepath'])
        if (destpath not in destpaths):
            if (not os.path.exists(destpath)):
                os.makedirs(destpath)
            destpaths[destpath]=True
            
        print (u"\t\t{}".format(file))
        if (not DRY_RUN):
            move(
                file, 
                os.path.join('.dup',file),
            )
        

print("Removed {}".format(format_bytes(total_size)))
