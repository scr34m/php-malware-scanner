<?php

/*
 * Copyright (c) 2016 Gabor Gyorvari
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *  http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

class MalwareScanner
{
    //Pretty Colors
    private $ANSI_GREEN        = "\033[32m";
    private $ANSI_RED          = "\033[31m";
    private $ANSI_YELLOW       = "\033[33m";
    private $ANSI_BLUE         = "\033[36m";
    private $ANSI_OFF          = "\033[0m";

    private $dir               = '';
    private $extension         = '.php';
    private $flagBase64        = false;
    private $flagChecksum      = false;
    private $flagComments      = false;
    private $flagHideOk        = false;
    private $flagHideWhitelist = false;
    private $flagNoStop        = false;
    private $flagPattern       = false;
    private $flagTime          = false;
    private $extraCheck        = false;
    private $whitelist         = array();
    private $ignore            = array();
    private $stat              = array(
                                 'directories' => 0,
                                 'files_scanned' => 0,
                                 'files_infected' => 0,
                                 );
    private $followSymlink = false;

    //Pattern File Attributes
    private $patterns_raw          = array();
    private $patterns_iraw         = array();
    private $patterns_re           = array();
    private $patterns_b64functions = array();
    private $patterns_b64keywords  = array();

    //Constructor - Likes to do as little as possible.
    public function __construct()
    {
        //Read Run Options
        $this->parseArgs();

        //Initiate Scan       
        $this->run($this->dir);
    }

    //Allows the -n/--no-color flag to easily remove color characters.
    private function disableColor()
    {
        $this->ANSI_GREEN  = '';
        $this->ANSI_RED    = '';
        $this->ANSI_YELLOW = '';
        $this->ANSI_BLUE   = '';
        $this->ANSI_OFF    = '';
    }

    //Prints the passed 'string' in red text, calls showHelp().
    //Exits
    private function error($msg)
    {
        echo $this->ANSI_RED . 'Error: ' . $msg . $this->ANSI_OFF . PHP_EOL;
        $this->showHelp();
        echo PHP_EOL . $this->ANSI_RED . 'Quiting' . PHP_EOL;
        exit(-1);
    }

    //Handles pattern loading and saving to the class object
    private function initializePatterns()
    {
	//Loads either the primary scanning patterns or the base64 patterns depending on -b/--base64 flag
        if (!$this->flagBase64) {
            $this->patterns_raw  = $this->loadPatterns(dirname(__FILE__) . '/definitions/patterns_raw.txt');
            $this->patterns_iraw = $this->loadPatterns(dirname(__FILE__) . '/definitions/patterns_iraw.txt');
            $this->patterns_re   = $this->loadPatterns(dirname(__FILE__) . '/definitions/patterns_re.txt');
        }
        else {
            $this->patterns_b64functions = $this->loadPatterns(dirname(__FILE__). '/base64_patterns/php_functions.txt');
            $this->patterns_b64keywords   = $this->loadPatterns(dirname(__FILE__). '/base64_patterns/php_keywords.txt');
        }
	    
        //Adds additional checks to patterns_raw
	//This may be something to move into a pattern file rather than leave hardcoded.
        if ($this->extraCheck) {
            $this->patterns_raw['googleBot'] = '# ';
            $this->patterns_raw['htaccess'] = '# ';
        }
    }

    //Check if the md5 checksum exists in the whitelist and returns true if it does.
    private function inWhitelist($hash)
    {
        return in_array($hash, $this->whitelist);
    }

    //Check if -i/--ignore flag listed this path to be omitted.
    private function isIgnored($pathname)
    {
        foreach ($this->ignore as $pattern) {
            $match = $this->pathMatches($pathname, $pattern);
            if ($match) {
                return true;
            }
        }
        return false;
    }

    //Loads individual pattern files
    //Skips blank linese
    //Stores most recent comment with the pattern in the list[] array
    //Returns an array of patterns:comments in key:value pairs
    private function loadPatterns($file)
    {
        $last_comment = '';
        $list = array();
        if (is_readable($file)) {
            foreach (file($file) as $pattern) {
                //Check if the line is only whitespace and skips.
                if (strlen(trim($pattern)) == 0) {
                    continue;
                }
                //Check if first char in pattern is a '#' which indicates a comment and skips.
		//Stores the comment to be stored with the pattern in the list as key:value pairs.
		//The pattern is the key and the comment is the value.
                if ($pattern[0] === '#') {
                    $last_comment = $pattern;
                    continue;
                }
                $list[trim($pattern)] = trim($last_comment);
            }
        }
        return $list;
    }

    //Loads the whitelist file
    private function loadWhitelist()
    {
        if (!is_file(__DIR__ . '/whitelist.txt')) {
            return;
        }
        $fp = fopen(__DIR__ . '/whitelist.txt', 'r');
        while (!feof($fp)) {
            $line = fgets($fp);
            $this->whitelist[] = substr($line, 0, 32);
        }
    }

    //Handles the getopt() function call, sets attributes according to flags.
    //All flag handling stuff should be setup here.
    private function parseArgs()
    {
        $options = getopt( 'd:e:i:abmcxlhkwnspt', 
                            array(
                                  'directory:', 
                                  'extension:', 
                                  'ignore:', 
                                  'all-output', 
                                  'base', 
                                  'checksum', 
                                  'comment', 
                                  'extra-check', 
                                  'follow-link', 
                                  'help', 
                                  'hide-ok', 
                                  'hide-whitelist', 
                                  'no-color', 
                                  'no-stop', 
                                  'pattern', 
                                  'time'
                            ));
        
        //Help Option should be first 
        if (isset($options['help']) || isset($options['h'])) {
            $this->showHelp();
            exit;
        }
        
        //Options that Require Additional Parameters
        if (isset($options['directory']) || isset($options['d'])) {
            $this->dir = isset($options['directory']) ? $options['directory'] : $options['d'];
        }
        if (isset($options['extension']) || isset($options['e'])) {
            $ext = isset($options['extension']) ? $options['extension'] : $options['e'];
            if ($ext[0] != '.') {
                $ext = '.' . $ext;
            }
            $this->extension = strtolower($ext);
        }
        if (isset($options['ignore']) || isset($options['i'])) {
            $tmp = isset($options['ignore']) ? $options['ignore'] : $options['i'];
            $this->ignore = is_array($tmp) ? $tmp : array($tmp);
        }

        //Simple Flag Options
        if (isset($options['all-output']) || isset($options['a'])) {
            $this->flagChecksum = true; $this->flagComments = true; $this->flagPattern = true; $this->flagTime = true;
        }
        if (isset($options['base64']) || isset($options['b'])) {
            $this->flagBase64 = true;
        }
	if (isset($options['checksum']) || isset($options['m'])) {
            $this->flagChecksum = true;
        }
        if (isset($options['comment']) || isset($options['c'])) {
            $this->flagComments = true;
        }
        if (isset($options['extra-check']) || isset($options['x'])) {
            $this->extraCheck = true;
        }
        if (isset($options['follow-symlink']) || isset($options['l'])) {
            $this->followSymlink = true;
        }
        if (isset($options['hide-ok']) || isset($options['k'])) {
            $this->flagHideOk = true;
        }
        if (isset($options['hide-whitelist']) || isset($options['w'])) {
            $this->flagHideWhitelist = true;
        }
        if (isset($options['no-color']) || isset($options['n'])) {
            $this->disableColor();
        }
        if (isset($options['no-stop']) || isset($options['s'])) {
            $this->flagNoStop = true;
        }
        if (isset($options['pattern']) || isset($options['p'])) {
            $this->flagPattern = true;
        }
        if (isset($options['time']) || isset($options['t'])) {
            $this->flagTime = true;
        }
    }

    // @see http://stackoverflow.com/a/13914119
    private function pathMatches($path, $pattern, $ignoreCase = false)
    {
        $expr = preg_replace_callback(
            '/[\\\\^$.[\\]|()?*+{}\\-\\/]/',
            function ($matches) {
                switch ($matches[0]) {
                    case '*':
                        return '.*';
                    case '?':
                        return '.';
                    default:
                        return '\\' . $matches[0];
                }
            },
            $pattern
        );

        $expr = '/' . $expr . '/';
        if ($ignoreCase) {
            $expr .= 'i';
        }

        return (bool)preg_match($expr, $path);
    }

    /*
    Formats and prints the scan result output line by line.
    Depending on specified options, it will print:
    -Status code
    -Last Modified Time
    -MD5 Hash
    -File Path
    -Pattern Matched
    -The last comment to appear in the pattern file before this pattern
    */
    private function printPath(&$found, &$path, &$pattern, &$comment, &$hash)
    {
        $output_string = '# ';

        //OK
        if (!$found) {
            if ($this->flagHideOk){return;}
            $state = 'OK';
            $hash = '                                ';
            $state_color = $this->ANSI_GREEN;
        }
        //WL
        elseif ($this->inWhitelist($hash)) {
            if ($this->flagHideWhitelist) {return;}
            $state = 'WL';
            $state_color = $this->ANSI_YELLOW;
        }
        //ER
        else {
            $state = 'ER';
            $state_color = $this->ANSI_RED;
        }
        $output_string = $state_color . $output_string . $state . $this->ANSI_OFF . ' ';

        //Include cTime
        if ($this->flagTime) {
            $changed_time = filectime($path);
            $htime = date('H:i d-m-Y', $changed_time);
            $output_string = $output_string . $this->ANSI_BLUE   . $htime . $this->ANSI_OFF . ' ';
        }

        //Include Checksum/Hash
        if ($this->flagChecksum) {
            $output_string = $output_string . $this->ANSI_BLUE   .  $hash . $this->ANSI_OFF . ' ';
        }

        //Append Path
        //'#' and {} included to prevent accidental script execution attempts
        // in the event that script output is pasted into a root terminal
        $opath = '# ' . '{' . $path . '}';
        $output_string = $output_string . $opath . ' ';

        //'#' added again as code snippets have the potential to be valid shell commands
        if ($found) {
            if ($this->flagPattern) {
                $opatt = "# $pattern ";
                $output_string = $output_string . $state_color . $opatt . $this->ANSI_OFF;
            }
            if ($this->flagComments) {
                $output_string = $output_string . $this->ANSI_BLUE . $comment . $this->ANSI_OFF;
            }
        }

        $output_string = $output_string . PHP_EOL;

        echo $output_string;
    }

    //Recursively scales the file system.
    //Calls the scan() function for each file found.
    private function process($dir)
    {
        $dh = opendir($dir);
        if (!$dh) {
            return;
        }
        $this->stat['directories']++;
        while (($file = readdir($dh)) !== false) {
            if ($file == '.' || $file == '..') {
                continue;
            }
            if ($this->isIgnored($dir . $file)) {
                continue;
            }
            if (!$this->followSymlink && is_link($dir . $file)) {
                continue;
            }
            if (is_dir($dir . $file)) {
                $this->process($dir . $file . '/');
            } elseif (is_file($dir . $file)) {
                $ext = strtolower(substr($file, strrpos($file, '.')));
                if ($ext == $this->extension) {
                    $this->scan($dir . $file);
                }
            }
        }
        closedir($dh);
    }

    //Prints stats on the run.
    private function report($start, $dir)
    {
        $end = time();
        echo 'Start time: ' . strftime('%Y-%m-%d %H:%M:%S', $start) . PHP_EOL;
        echo 'End time: ' . strftime('%Y-%m-%d %H:%M:%S', $end) . PHP_EOL;
        echo 'Total execution time: ' . ($end - $start) . PHP_EOL;
        echo 'Base directory: ' . $dir . PHP_EOL;
        echo 'Total directories scanned: ' . $this->stat['directories'] . PHP_EOL;
        echo 'Total files scanned: ' . $this->stat['files_scanned'] . PHP_EOL;
        echo 'Total malware identified: ' . $this->stat['files_infected'] . PHP_EOL;
    }

    //Validates the input directory
    //Calls the load pattern and load whitelist functions
    //Calls the process and report functions.
    private function run($dir)
    {   
        //Make sure a directory was specified.
        if  ($this->dir === '') {
            $this->error('No directory specified');
        }
        
        //Make sure the input is a valid directory path.
        $dir = rtrim($dir, '/');
        if (!is_dir($dir)) {
            $this->error('Specified path is not a directory: ' . $dir);
        }
        
	//Load Patterns
        $this->initializePatterns();
	
	//Load Whitelist
	$this->loadWhitelist();
	    
        $start = time();
        $this->process($dir . '/');
        $this->report($start, $dir . '/');
    }

    //Loads target file contents for scanning
    //Initiates the multiple scan types by calling the scanLoop function
    private function scan($path)
    {
        $this->stat['files_scanned']++;
        $fileContent = file_get_contents($path);
        $found = false;
        $hash  = '';
        $toSearch = '';
        $comment = '';

        if (!$this->flagBase64) {
            $this->scanLoop('scanFunc_STR',  $fileContent, $this->patterns_raw,  $path, $found, $hash);
            $this->scanLoop('scanFunc_STRI', $fileContent, $this->patterns_iraw, $path, $found, $hash);
            $this->scanLoop('scanFunc_RE',   $fileContent, $this->patterns_re,   $path, $found, $hash);
        }
        else {
            $this->scanLoop('scanFunc_STR',  $fileContent, $this->patterns_b64functions,  $path, $found, $hash);
            $this->scanLoop('scanFunc_STR',  $fileContent, $this->patterns_b64keywords,  $path, $found, $hash);
        }

        if (!$found) {
            $this->printPath($found, $path, $toSearch, $comment, $hash);
            return false;
        }

        if ($found && $this->inWhitelist($hash)) {
            return false;
        }

	$this->stat['files_infected']++;
        return true;
    }

    //Performs raw string, case sensitive matching.
    //Returns true if the raw string exists in the file contents.
    private function scanFunc_STR(&$pattern, &$content)
    {
        return (strpos($content, $pattern) !== false);
    }

    //Performs raw string, case insensitive matching.
    //Returns true if the raw string exists in the file contents, ignoring case.
    private function scanFunc_STRI(&$pattern, &$content)
    {
        return (stripos($content, $pattern) !== false);
    }

    //Performs regular expression matching.
    //Returns true if the Regular Expression matches something in the file.
    //Patterns will match multiple lines, though you can use ^$ to match the beginning and end of a line.
    private function scanFunc_RE(&$pattern, &$content)
    {
        return preg_match('/' . $pattern . '/im', $content);
    }

    //First parameter '$scanFunction' is a defined function name passed as a string.
    //This function should accept a pattern string and a content string.
    //This function will return true if the pattern exists in the content.
    //See 'scanFunc_STR', 'scanFunc_STRI', 'scanFUNC_RE' above as examples.
	
    //Loops through all patterns in a file using the passed function name to determine a match.
    //Variables passed by reference for performance and modification access.
    private function scanLoop($scanFunction, &$fileContent, &$patterns, &$path, &$found, &$hash)
    {
        if (!$found || $this->flagNoStop) {
            foreach ($patterns as $pattern => $comment) {
		//Call the function that is named in $scanFunction
		//This allows multiple search/match functions to be used without duplicating the loop code.
                if ($this->$scanFunction($pattern, $fileContent)) {
                    $found = true;
                    if ($hash === ''){$hash = md5($fileContent);}
                    $this->printPath($found, $path, $pattern, $comment, $hash);
                    if (!$this->flagNoStop){return;}
                }
            }
        }
    }

    //Prints out the usage menu options.
    private function showHelp()
    {
        echo 'Usage: php scan.php -d <directory>'                                                                   . PHP_EOL;
        echo '    -h                   --help             Show this help message'                                   . PHP_EOL;
        echo '    -d <directory>       --directory        Directory for searching'                                  . PHP_EOL;
        echo '    -e <file extension>  --extension        File Extension to Scan'                                   . PHP_EOL;
        echo '    -i <directory|file>  --ignore           Directory of file to ignore'                              . PHP_EOL;
        echo '    -a                   --all-output       Enables --checksum,--comment,--pattern,--time'            . PHP_EOL;
        echo '    -b                   --base64           Scan for base64 encoded PHP keywords'                     . PHP_EOL;	    
        echo '    -m                   --checksum         Display MD5 Hash/Checksum of file'                        . PHP_EOL;
        echo '    -c                   --comment          Display comments for matched patterns'                    . PHP_EOL;
        echo '    -x                   --extra-check      Adds GoogleBot and htaccess to Scan List'                 . PHP_EOL;
        echo '    -l                   --follow-symlink   Follow symlinked directories'                             . PHP_EOL;
        echo '    -k                   --hide-ok          Hide results with \'OK\' status'                          . PHP_EOL;
        echo '    -w                   --hide-whitelist   Hide results with \'WL\' status'                          . PHP_EOL;
        echo '    -n                   --no-color         Disable color mode'                                       . PHP_EOL;
        echo '    -s                   --no-stop          Continue scanning file after first hit'                   . PHP_EOL;
        echo '    -p                   --pattern          Show Patterns next to the file name'                      . PHP_EOL;
        echo '    -t                   --time             Show time of last file change'                            . PHP_EOL;
    }

}

//Creates a new MalwareScanner object which does all the work.
new MalwareScanner();
?>
