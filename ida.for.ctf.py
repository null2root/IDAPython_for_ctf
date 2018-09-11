
import idaapi


## init

hotkey_getbytes 	= 'SHIFT+C'
hotkey_setbaseaddr 	= 'SHIFT+H'


_id = CreateArray('__uselessaddon__')
if _id == -1:
	_id = GetArrayId('__uselessaddon__')

IDX_SETBASEADDR = 0
SetArrayLong( _id, IDX_SETBASEADDR, 0x0)

DelHotkey(hotkey_getbytes)
DelHotkey(hotkey_setbaseaddr)


def hexdump(addr, src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("0x%08x(0x%08x)  %-*s  %s\n" % (c+addr, c, length*3, hex, printable))
    return ''.join(lines)

def getbytes(n=0x30, addr = -1):
	if addr == -1:
		addr = ScreenEA()

	data = get_bytes(addr, n)

	print '----------------------------------- getbytes(n, addr) --------------------------------------'
	print '[*] addr  : 0x%08x'%addr

	try:
		arrId = GetArrayId('__uselessaddon__')
		baseaddr = GetArrayElement(AR_LONG, arrId, IDX_SETBASEADDR)
		if baseaddr > 0:
			print '[*] ++addr : 0x%08x'%(baseaddr+addr)
	except Exception as ex:
		pass

	print '[*] hex   : ' + data.encode('hex')
	print '[*] ascii : ' + data
	print hexdump(addr, data)
	print 'data = \'%s\''%(''.join(['\\x%02x'%ord(i) for i in data]))
	print ''

	return

def setbaseaddr():
	addr = AskStr('0x0000555555554000', 'Set address of imagebase\n(If you get annoyed with PIE)')
	if addr == None:
		return
	try:
		addr = int(addr, 0x10)
		arrId = GetArrayId('__uselessaddon__')
		if False == arrId:
			print '[!] failed to get array'
			return

		if SetArrayLong( arrId, IDX_SETBASEADDR, addr):
			print '[*] set baseaddr to 0x%08x'%addr
		else:
			print '[!] failed to set baseaddr for some reason I dunno why :P'	
		
	except Exception as ex:
		print '[!] failed to set baseaddr. now in EXCEPT!'
		print ex
	
	return


idaapi.CompileLine('static getbytes() { RunPythonStatement("getbytes()");}')
idaapi.CompileLine('static setbaseaddr() { RunPythonStatement("setbaseaddr()");}')
AddHotkey(hotkey_getbytes, 'getbytes')
AddHotkey(hotkey_setbaseaddr, 'setbaseaddr')

helpmsg = '''
===== SOME USELESS ADDON =====
[shift+c] show address information & hexdump (for copy/paste when write some stuff.. exploit.. exploit.. exploit.)
[shift+h] set image base address (when binary compiled with PIE.. 0x0000555555554000!?)
==============================
'''
print helpmsg

