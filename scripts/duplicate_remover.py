from os import listdir, remove
from os.path import isfile, join, getsize
from collections import defaultdict
from dataclasses import dataclass

import sys
import glob
import json

@dataclass
class File():
    path: str
    size: int

if len(sys.argv) != 2:
    exit(1)

dirname = None

if sys.argv[1][-1] == '/':
    dirname = sys.argv[1]
else:
    dirname = sys.argv[1] + '/'

all_files = glob.glob(dirname + '*.json')

all_files_dict = defaultdict(list)

for file in all_files:
    file_size = getsize(file)
    file_name = ""

    with open(file) as json_file:
        data = json.load(json_file)
        file_name = data[0]['data']['children'][0]['data']['name']

    all_files_dict[file_name].append(File(file, file_size))

for a in all_files_dict:
    print(a, ",", all_files_dict[a])

    thread_name = a
    thread_list = all_files_dict[a]

    sizes = []

    if len(thread_list) == 1:
        continue

    for thread in thread_list:
        sizes.append(thread.size)

    if len(set(sizes)) == 1:
        for thread in range(len(thread_list) - 1):
            remove(thread_list[thread].path)
    else:
        sizes_sorted = sorted(set(sizes), key=int)
        best_size = sizes_sorted[-1]

        for thread in thread_list:
            if thread.size != best_size:
                remove(thread.path)
