## Introduction
This script will scan each file in a tar archive with a Yara rule. All of this is done in memory so no extraction to disk has to occur. There is a flag to allow files within the archive that do match to be automatically extracted. 

Why? If you have lots of files that are being archived, this tool is perfect because it can look inside the archive with a Yara signature and extract the file which matches the Yara signature.

## Help output

```bash
usage: extract_scan.py [-h] -f TAR_FILE -r YARARULE_FILE
                       [-e EXTRACT_DIRECTORY] [-s] [--version]

Will scan each file in a tar archive with a yara rule. Matches will display on
stdout. There are options to show each string match and to extract file
matches to folder. Example: python extract_scan.py -f files.tar -r rule.yara
-e myextractiondir

optional arguments:
  -h, --help            show this help message and exit
  -f TAR_FILE           Path of the .tar file (required)
  -r YARARULE_FILE      Path of the Yara rule file (required)
  -e EXTRACT_DIRECTORY  Path to extract files that match Yara signature
                        (optional)
  -s                    yara: print matching strings (optional)
  --version             show program's version number and exit
```

## Example
Three files are put into an tar archive `myfiles.tar`. Each file contains a single word at the top.

```
$ head file*
==> file1.txt <==
apples

==> file2.txt <==
oranges

==> file3.txt <==
blueberry

tar -cvf myfiles.tar ./
```

A Yara signature is created looking for the string `blueberry`
```
$ cat rule.yara
rule FileWithBlueberry
{
    strings:
        $find_string_file = "blueberry"

    condition:
        any of them
}
```

The script is ran against the tar archive with the Yara rule and a folder to extract matches is specified. The Yara arule matches on `file3.txt'
```bash
$ python extract_scan.py -f myfiles.tar -r rule.yara -e matchesFolder
'./file3.txt' FileWithBlueberry
```

The context were automatically extracted and saved to the specified folder.

```bash
$ cat matchesFolder/file3.txt
blueberry
```
## License
* Apache 2.0