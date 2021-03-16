Javascript Zipper
=================

Made this because I couldn't install 7zip on a particular PC but i needed to read ZIP files.
Windows Explorer can only read ZipCrypto encrypted files, not AES encrypted ZIP.

This is just a temporary solution to the problem, AES Zip mostly works but ZipCrypto encryption
is a little iffy.

Uses the [pako](https://github.com/nodeca/pako) library for the INFLATE and DEFLATE implementations.
