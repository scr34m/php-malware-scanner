PHP malware scanner
===================

Traversing directories for files with php extensions and testing files against text or regexp rules, the rules based on self gathered samples and publicly vailable malwares/webshells.
The goal is to find infected files and fight against kiddies, because to easy to bypass rules.

How to use?
-----------

```
Usage: php scan.php -d <directory>
    -h                   --help             Show this help message
    -d <directory>       --directory        Directory for searching
    -e <file extension>  --extension        File Extension to Scan
    -i <directory|file>  --ignore           Directory of file to ignore
    -a                   --all-output       Enables --checksum,--comment,--pattern,--time
    -b                   --base64           Scan for base64 encoded PHP keywords
    -m                   --checksum         Display MD5 Hash/Checksum of file
    -c                   --comment          Display comments for matched patterns
    -x                   --extra-check      Adds GoogleBot and htaccess to Scan List
    -l                   --follow-symlink   Follow symlinked directories
    -k                   --hide-ok          Hide results with 'OK' status
    -w                   --hide-whitelist   Hide results with 'WL' status
    -n                   --no-color         Disable color mode
    -s                   --no-stop          Continue scanning file after first hit
    -p                   --pattern          Show Patterns next to the file name
    -t                   --time             Show time of last file change
```

Ignore argument could be used multiple times and accept glob style matching ex.: "cache*", "??-cache.php" or "/cache" etc.

Extension argument defaults to .php .

--base64 is an alternative scan mode which ignores the main pattern files and uses a large list of php keywords and functions that have been converted to base64.  Slower and prone to false positives, but gives additional base64 scanning coverage.  These pattern files are located in base64_patterns and were derived from php 7 keywords and functions.  Not many PHP extensions are included.

--comment flag will display the last comment to appear in the pattern file before the matched pattern,  so documenting the pattern files is important.

--pattern flag will display the pattern string that was matched.

Patterns
--------

There are three main pattern files the cover different typtes of pattern matching.  There is one pattern per line.  All lines where the very first character is a '#' is considered a comment and not used as a pattern.  Whitespace in the pattern files is not used.

-patterns_raw.txt  -- Raw string matching
-patterns-iraw.txt -- Case insensitive raw string matching
-patterns-re.txt   -- Regular expression matching.

Whitelisting
------------

See [whitelist.txt](https://github.com/scr34m/php-malware-scanner/blob/master/whitelist.txt) file for a predefined MD5 hash list. Only the first 32 characters are used, rest of the line ignored so feel free to leave a comment.

Tools
---------
-text2base64.py
  Takes a plaintext string as input and returns 3 base64 string equivalents.
  Python script that needs to be executed from the terminal to be used.
 
  Marking as executable is required.
  ~$ chmod +x text2base64.py
  
  It is worth noting that the presence of one of the three output strings in a block of text does not 100% guarantee that the string was
  present in the original code.  It is guaranteed that IF the subject string was present in the original code, then one of the three
  output strings will be present in the base64 version.
  
  usage:
  ./text2base64.py 'base64_decode'  
   YmFzZTY0X2RlY29kZ  
   Jhc2U2NF9kZWNvZG  
   iYXNlNjRfZGVjb2Rl  
  
  An example: The presence of 'YmFzZTY0X2RlY29kZ' does not guarantee that 'base64_decode' is in the plain text code.   
  It is guaranteed that IF 'base64_decode' was present in the plain text code, then one of these three base64 strings WILL be present.
  The presence of 'YmFzZTY0X2RlY29kZ' in a block of code may be because 'ase64_decod' was in the original code.  
  Note the missing edge characters which is due to bit misalignments and character bleed.

Resources
---------

* [PHPScanner](https://github.com/PHPScannr/phpFUS)
* [PMF - PHP Malware Finder](https://github.com/nbs-system/php-malware-finder)
* [check regexp online](http://www.phpliveregex.com)
* [malware samples 1](https://github.com/nbs-system/php-malware-finder/tree/master/php-malware-finder/samples)
* [malware samples 2](https://github.com/r4v/php-exploits)
* [malware samples 3](https://github.com/nikicat/web-malware-collection)
* [malware samples 4](https://github.com/antimalware/manul/tree/master/src/scanner/static/signatures)

Licensing
---------

PHP malware scanner is [licensed](https://github.com/scr34m/php-malware-scanner/blob/master/LICENSE.txt) under the GNU General Public License v3.
