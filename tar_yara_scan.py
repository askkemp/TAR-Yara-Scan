# Copyright 2017 Kemp Langhorne
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Purpose:  Will scan each file in a tar archive with a yara rule. All done in memory so no extraction to disk has to occur (unless desired).
# Input: Tar file. Yara file. See --help
# Output: Yara scan results. Only prints yara rule matches. Will extract files with yara matches if requsted.

import tarfile
import yara
import re
import argparse
import os 

# Command-line arguments
parser = argparse.ArgumentParser(description='Will scan each file in a tar archive with a yara rule. Matches will display on stdout. There are options to show each string match and to extract file matches to folder. Example: python %(prog)s -f files.tar -r rule.yara -e myextractiondir')
parser.add_argument('-f', action='store', dest='tar_file', required=True,
                    help='Path of the .tar file (required)')
parser.add_argument('-r', action='store', dest='yararule_file', required=True,
                    help='Path of the Yara rule file (required)')
parser.add_argument('-e', action='store', dest='extract_directory', required=False,
                    help='Path to extract files that match Yara signature (optional)')
parser.add_argument('-s', action='store_true', default=False,
                    dest='show_matching_strings',
                    help='yara: print matching strings (optional)')
parser.add_argument('--version', action='version', version='%(prog)s 1.0')
results = parser.parse_args()


# Quick check to see if files provided at command-line exist before continuing
if not os.path.isfile(results.tar_file):
    print "Error: Tar file %s not found" % results.tar_file
    exit()
if not os.path.isfile(results.yararule_file):
    print "Error: Yara file %s not found" % results.yararule_file
    exit()

# Provides feedback on all scans. e.g.
# {'tags': [], 'matches': True, 'namespace': 'default', 'rule': 'ExampleRule1', 'meta': {}, 'strings': [(8L, '$my_text_string', 'file')]}
# {'tags': [], 'matches': False, 'namespace': 'default', 'rule': 'ExampleRule1', 'meta': {}, 'strings': []}
def mycallback(data):
    # Important note: There is a match result dictionary for each rule inside compiled yara file.
    if data['matches'] == True:
        print member_filename, data['rule'] # Filename and yara rule name

        if results.extract_directory: # extract files from tar that match to specified directory by user
            tar.extract(member, path=results.extract_directory)

        if results.show_matching_strings: # show string matches if requested by user
            for tuple in data['strings']:
                print "\t", tuple
    return yara.CALLBACK_CONTINUE

# Loading yara rule
rules = yara.compile(filepath=results.yararule_file)

# Loading tar file and the scanning each archive file one at a time
tar = tarfile.open(results.tar_file, "r:")
for member in tar.getmembers(): # <TarInfo 'file3.txt' at 0x7fc3ddf4ac50>
     member_filename = re.findall("\'[^']+\'", str(member))[0] # Pull out filename using regex
     f = tar.extractfile(member)
     if f is not None: # Should only match on files
         content = f.read()
         matches = rules.match(data=content, callback=mycallback) # Yara
     #if f is None: # member is not a regular file or link. e.g. it could be a directory.
     #    print member



