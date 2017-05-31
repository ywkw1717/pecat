# pecat
This is the PE file analysis tool.

By the way, Kudo Haruka is very very cute.

I made this program to answer the question of seccamp 2017(A-6).

This program is revised edition.

You can do 2 things.

1. Header analysis
2. Parse of string resource(.NET Application)

## Usage
```sh
$ gcc pecat.c -o pecat
```
- Header analysis
```sh
$ pecat -c header FILE_NAME
```

- Parse of string resource(.NET Application)
```sh
$ pecat -c string FILE_NAME
```
