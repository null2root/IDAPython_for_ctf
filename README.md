# IDAPython_for_ctf
IDAPython script for ctf

* Well.. Actually not just for ctf.

## How to use

* Save this repo
* Press [Alt-F7] on IDA and select the file.
* Profit


## Keyboard shortcuts in IDA

<pre>
shift-c -- show address information & hexdump on cursor (for copy/paste when write some stuff)
shift-h -- set imagebase address (when binary compiled with PIE - like 0x0000555555554000)

//shift-e
//shift-s
</pre>

## Use function

<pre>
Python>getbytes(0x10, 0x00808)
----------------------------------- getbytes(n, addr) --------------------------------------
[*] addr  : 0x00000808
[*] hex   : 08202000000000000800000000000000
[*] ascii :   
0x00000808(0x00000000)  08 20 20 00 00 00 00 00 08 00 00 00 00 00 00 00   .  .............

data = '\x08\x20\x20\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'

Python>setbaseaddr()
[*] set baseaddr to 0x555555554000
Python>getbytes(0x20, 0x00808)
----------------------------------- getbytes(n, addr) --------------------------------------
[*] addr  : 0x00000808
[*] ++addr : 0x555555554808
[*] hex   : 082020000000000008000000000000000820200000000000301f200000000000
[*] ascii :   
0x00000808(0x00000000)  08 20 20 00 00 00 00 00 08 00 00 00 00 00 00 00   .  .............
0x00000818(0x00000010)  08 20 20 00 00 00 00 00 30 1f 20 00 00 00 00 00   .  .....0. .....

data = '\x08\x20\x20\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x08\x20\x20\x00\x00\x00\x00\x00\x30\x1f\x20\x00\x00\x00\x00\x00'
</pre>

