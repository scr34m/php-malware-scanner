<?php
function fetch($url, $file = false)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($ch, CURLOPT_VERBOSE, false);

    if ($file) {
        $fp = fopen($file, 'w');
        curl_setopt($ch, CURLOPT_FILE, $fp);
    } else {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    }

    $headers = array(
        // drupal suxx
        'Cookie: _px2=eyJ1IjoiZDZhNGM3MjAtYjZmNC0xMWVhLWI2MzMtNzk5YzRmZjM4ZmJkIiwidiI6IjQ0ZTFiMDQwLTRkZGUtMTFlOC1iMWRjLWYxNWU4OTg1NTZjNyIsInQiOjE1OTMwOTc2Mjg2NzAsImgiOiIzNzk5N2RkYTU3ZTI1NGY0ZDM5MmRiMWExNWZhZjhjNTZkMmM5NTZkZDJiZWVkZGVlZDc1MThiNTE5MTFjYzgwIn0=; _ga=GA1.2.2042202377.1525247839; _gat=1; _gid=GA1.2.1034461360.1593095881; has_js=1; _pxff_fp=1; _pxff_rf=1; pxvid=44e1b040-4dde-11e8-b1dc-f15e898556c7',
        'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
    );
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    if ($file) {
        curl_exec($ch);
        curl_close($ch);
        fclose($fp);
        return;
    } else {
        $content = trim(curl_exec($ch));
        curl_close($ch);
        return $content;
    }
}

function is_cached($file)
{
    global $cache_dir;

    return is_readable($cache_dir . '/' . $file);
}

function set_cache($file, $data, $algo, $hash)
{
    global $cache_dir;

    file_put_contents($cache_dir . '/' . $file, $data);
    file_put_contents($cache_dir . '/' . $file . '.' . $algo, $hash);
}

function get_cache($file)
{
    global $cache_dir;

    return file_get_contents($cache_dir . '/' . $file);
}

function hash_archive($fp, $file)
{
    global $cache_dir;

    $hash_file = $cache_dir . '/' . $file . '.hash';
    if (!is_file($hash_file)) {
        $f = fopen($hash_file, 'w');
        $fh = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator('phar://' . $cache_dir . '/' . $file),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($fh as $splFileInfo) {
            if ($splFileInfo->isFile()) {
                // store md5 hash we use that in the scanner
                fputs($f, md5(file_get_contents($splFileInfo->getPathname())) . "\n");
            }
        }
        fclose($f);
    }

    fputs($fp, file_get_contents($hash_file));
}

function fetch_jquery($fp)
{
    echo 'Fetching jQuery' . PHP_EOL;
    $data = fetch('https://code.jquery.com/jquery/');

    preg_match_all(
        '/<a class=\'open\-sri\-modal\' href=\'\/(jquery-.*?\.js)\' data\-hash=\'sha256\-(.*?)\'/',
        $data,
        $m
    );
    foreach ($m[1] as $k => $file) {
        if (!is_cached($file)) {
            echo 'Downloading: ' . 'https://code.jquery.com/' . $file . PHP_EOL;
            $data = fetch('https://code.jquery.com/' . $file) . PHP_EOL;
            if (base64_encode(hash('sha256', $data, true)) != $m[2][$k]) {
                die('Hash mismatch' . PHP_EOL);
            }
            set_cache($file, $data, 'sha256', bin2hex(base64_decode($m[2][$k])));
        } else {
            $data = get_cache($file);
        }

        // store md5 hash we use that in the scanner
        fputs($fp, md5($data) . "\n");
    }
}

function fetch_archive($file, $url, $hash, $algo, $hash_url = null)
{
    $tmp = __DIR__ . 'dl.tar.gz';
    if (!is_cached($file)) {
        echo 'Downloading: ' . $url . PHP_EOL;
        fetch($url, $tmp);
        if (!empty($hash_url)) {
            echo 'Downloading hash: ' . $hash_url . PHP_EOL;
            $hash = fetch($hash_url);
        }
        $data_hash = hash_file($algo, $tmp);
        if ($data_hash != $hash) {
            die('Hash mismatch: ' . $data_hash . ' != ' . $hash . PHP_EOL);
        }
        set_cache($file, file_get_contents($tmp), $algo, $hash);
    }
}

// Ignored releases are: beta, RC, strayhorn, mingus, delta, gold and mu by regexp and 1.0.2 because no sha1
function fetch_wordpress($fp)
{
    echo 'Fetching Wordpress' . PHP_EOL;
    $data = fetch('https://wordpress.org/download/releases/');

    preg_match_all(
        '/<a href="(https:\/\/wordpress\.org\/(wordpress\-([0-9.]+)\.tar\.gz))">/',
        $data,
        $m
    );
    foreach ($m[2] as $k => $file) {
        if ($m[2][$k] == 'wordpress-1.0.2.tar.gz') {
            // no sha1 info
            continue;
        }
        fetch_archive($m[2][$k], $m[1][$k], null, 'sha1', $m[1][$k] . '.sha1');
        hash_archive($fp, $file);
    }
}

// Ignores: snapshots, rc, beta, alpha
function fetch_typo3($fp)
{
    echo 'Fetching Typo3' . PHP_EOL;
    $data = json_decode(fetch('https://get.typo3.org/json'));
    foreach ($data as $value) {
        if (isset($value->releases)) {
            foreach ($value->releases as $release) {
                if (strstr($release->version, 'snapshot') || strstr($release->version, 'rc') || strstr($release->version, 'beta') || strstr($release->version, 'alpha')) {
                    // ignoring snapshots
                    continue;
                }
                if (in_array($release->version, ['4.6.0', '4.5.33', '3.3.0'])) {
                    // The specified blob does not exist.
                    // 3.3.0 is damaged archive
                    continue;
                }
                $file = 'type3-' . $release->version . '.tar.gz';
                fetch_archive($file, 'https://get.typo3.org' . $release->url->tar, $release->checksums->tar->sha1, 'sha1');
                hash_archive($fp, $file);
            }
        }
    }
}

function fetch_pagekit($fp)
{
    echo 'Fetching Pagekit' . PHP_EOL;
    $data = json_decode(fetch('https://pagekit.com/api/update'));
    foreach ($data as $k => $releases) {
        if ($k == 'latest') {
            $releases = [$releases];
        }
        foreach ($releases as $release) {
            $file = 'pagekit-' . $release->version . '.tar.gz';
            fetch_archive($file, $release->url, $release->shasum, 'sha1');
            hash_archive($fp, $file);
        }
    }
}

// Ignored releases are: alpha, beta, rc, dev
function fetch_drupal($fp)
{
    echo 'Fetching Drupal ' . PHP_EOL;

    $page = 0;
    $pages = false;
    do {
        $data = fetch('https://www.drupal.org/project/drupal/releases?page=' . $page);

        // pagination init
        if ($pages === false && preg_match('/\?page=(\d+)">last »<\/a>/', $data, $m)) {
            $pages = $m[1];
        }

        preg_match_all(
            '/<a href="(\/project\/drupal\/releases\/(\d\.\d\.\d))">drupal/i',
            $data,
            $m
        );
        foreach ($m[1] as $k => $ver_uri) {
            $ver_data = fetch('https://www.drupal.org' . $ver_uri);
            if (!preg_match('/<span class="field-content hash">([a-z0-9]+)<\/span>/i', $ver_data, $ver_m)) {
                die('Missing hash info: ' . $m[2][$k]);
            }
            $file = 'drupal-' . $m[2][$k] . '.tar.gz';
            fetch_archive($file, 'https://ftp.drupal.org/files/projects/' . $file, $ver_m[1], 'md5');
            hash_archive($fp, $file);
        }

        if ($pages === false) {
            break;
        }
        $page++;
    } while ($page <= $pages);
}

function fetch_joomla($fp, $versions)
{
    foreach ($versions as $version => $id) {
        echo 'Fetching Joomla ' . $version . PHP_EOL;

        $data = fetch('https://downloads.joomla.org/cms/joomla' . $id);
        preg_match_all('/href="(\/cms\/joomla\d+\/(\d+\-\d+\-\d+))"/', $data, $m);
        foreach ($m[1] as $k => $url) {
            $file = 'joomla_' . $m[2][$k] . '-stable-full_package.tar.gz';

            // pre check because we need hash information
            if (!is_cached($file)) {
                $data = fetch('https://downloads.joomla.org' . $url);

                if (!preg_match('/Joomla! '.str_replace('-', '\.', $m[2][$k]).' Full Package \(\.tar\.gz\).*?SHA1 Signature\s*<\/dt>\s*<dd>\s*([a-z0-9]{40})\s*<\/dd>/is', $data, $m2)) {
                    echo 'Unable to find SHA1 signature for version ' . $m[2][$k] . PHP_EOL;
                    break;
                }

                if (!preg_match('/href="('.preg_quote($url, '/').'\/.*?format=gz)"/', $data, $m3)) {
                    echo 'Unable to find archive url for version ' . $m[2][$k] . PHP_EOL;
                    break;
                }

                fetch_archive($file, 'https://downloads.joomla.org' . $m3[1], $m2[1], 'sha1');
            }

            hash_archive($fp, $file);
        }
    }
}

if ($argc == 2) {
    $cache_dir = $argv[1];
} else {
    $cache_dir = __DIR__ . '/cache';
}

if (!is_readable($cache_dir)) {
    if (!mkdir($cache_dir)) {
        die('Unable to create cache directory');
    }
}

$fp = fopen('all.txt', 'w');

// TODO https://modx.com/download/other-downloads
// TODO wordpress plugins only popular ones

fetch_jquery($fp);
fetch_wordpress($fp);
fetch_typo3($fp);
fetch_pagekit($fp);
fetch_drupal($fp);
fetch_joomla($fp, ['3.0' => 3, '2.5' => 25, '1.5' => 15, '1.0' => 10]);

fclose($fp);

echo 'Creating unique database' . PHP_EOL;
exec('sort -u -o unique.txt all.txt');

echo 'Compressing all.txt' . PHP_EOL;
exec('gzip < unique.txt > compressed.dat'); // gzencode

$hash = hash_file('sha256', 'compressed.dat');
file_put_contents('compressed.sha256', $hash);
echo 'SHA256 is ' . $hash . PHP_EOL;