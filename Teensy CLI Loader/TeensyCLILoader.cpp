/* Teensy Loader, Command Line Interface
* Program and Reboot Teensy Board with HalfKay Bootloader
* http://www.pjrc.com/teensy/loader_cli.html
* Copyright 2008-2010, PJRC.COM, LLC
*
* You may redistribute this program and/or modify it under the terms
* of the GNU General Public License as published by the Free Software
* Foundation, version 3 of the License.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see http://www.gnu.org/licenses/
*/

/* Want to incorporate this code into a proprietary application??
* Just email paul@pjrc.com to ask.  Usually it's not a problem,
* but you do need to ask to use this code in any way other than
* those permitted by the GNU General Public License, version 3  */

/* For non-root permissions on ubuntu or similar udev-based linux
* http://www.pjrc.com/teensy/49-teensy.rules
*/


#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <Windows.h>


void usage(const char *err)
{
	if (err != NULL) fprintf(stderr, "%s\n\n", err);
	fprintf(stderr,
		"Usage: teensy_loader_cli --mcu=<MCU> [-w] [-h] [-n] [-v] <file.hex>\n"
		"\t-w : Wait for device to appear\n"
		"\t-r : Use hard reboot if device not online\n"
		"\t-s : Use soft reboot if device not online (Teensy3.x only)\n"
		"\t-n : No reboot after programming\n"
		"\t-v : Verbose output\n"
		"\nUse `teensy_loader_cli --list-mcus` to list supported MCUs.\n"
		"\nFor more information, please visit:\n"
		"http://www.pjrc.com/teensy/loader_cli.html\n");
	exit(1);
}

// USB Access Functions
int teensy_open(void);
int teensy_write(void *buf, int len, double timeout);
void teensy_close(void);
int hard_reboot(void);
int soft_reboot(void);

// Intel Hex File Functions
int read_intel_hex(const char *filename);
int ihex_bytes_within_range(int begin, int end);
void ihex_get_data(int addr, int len, unsigned char *bytes);
int memory_is_blank(int addr, int block_size);

// Misc stuff
int printf_verbose(const char *format, ...);
void delay(double seconds);
void die(const char *str, ...);
void parse_options(int argc, char **argv);

// options (from user via command line args)
int wait_for_device_to_appear = 0;
int hard_reboot_device = 0;
int soft_reboot_device = 0;
int reboot_after_programming = 1;
int verbose = 0;
int code_size = 0, block_size = 0;
const char *filename = NULL;


/****************************************************************/
/*                                                              */
/*                       Main Program                           */
/*                                                              */
/****************************************************************/

int main(int argc, char **argv)
{
	unsigned char buf[2048];
	int num, addr, r, write_size = block_size + 2;
	int first_block = 1, waited = 0;

	// parse command line arguments
	parse_options(argc, argv);
	if (!filename) {
		usage("Filename must be specified");
	}
	if (!code_size) {
		usage("MCU type must be specified");
	}
	printf_verbose("Teensy Loader, Command Line, Version 2.0\n");

	// read the intel hex file
	// this is done first so any error is reported before using USB
	num = read_intel_hex(filename);
	if (num < 0) die("error reading intel hex file \"%s\"", filename);
	printf_verbose("Read \"%s\": %d bytes, %.1f%% usage\n",
		filename, num, (double)num / (double)code_size * 100.0);

	// open the USB device
	while (1) {
		if (teensy_open()) break;
		if (hard_reboot_device) {
			if (!hard_reboot()) die("Unable to find rebootor\n");
			printf_verbose("Hard Reboot performed\n");
			hard_reboot_device = 0; // only hard reboot once
			wait_for_device_to_appear = 1;
		}
		if (soft_reboot_device) {
			if (soft_reboot()) {
				printf_verbose("Soft reboot performed\n");
			}
			soft_reboot_device = 0;
			wait_for_device_to_appear = 1;
		}
		if (!wait_for_device_to_appear) die("Unable to open device\n");
		if (!waited) {
			printf_verbose("Waiting for Teensy device...\n");
			printf_verbose(" (hint: press the reset button)\n");
			waited = 1;
		}
		delay(0.25);
	}
	printf_verbose("Found HalfKay Bootloader\n");

	// if we waited for the device, read the hex file again
	// perhaps it changed while we were waiting?
	if (waited) {
		num = read_intel_hex(filename);
		if (num < 0) die("error reading intel hex file \"%s\"", filename);
		printf_verbose("Read \"%s\": %d bytes, %.1f%% usage\n",
			filename, num, (double)num / (double)code_size * 100.0);
	}

	// program the data
	printf_verbose("Programming");
	fflush(stdout);
	for (addr = 0; addr < code_size; addr += block_size) {
		if (!first_block && !ihex_bytes_within_range(addr, addr + block_size - 1)) {
			// don't waste time on blocks that are unused,
			// but always do the first one to erase the chip
			continue;
		}
		if (!first_block && memory_is_blank(addr, block_size)) continue;
		printf_verbose(".");
		if (block_size <= 256 && code_size < 0x10000) {
			buf[0] = addr & 255;
			buf[1] = (addr >> 8) & 255;
			ihex_get_data(addr, block_size, buf + 2);
			write_size = block_size + 2;
		}
		else if (block_size == 256) {
			buf[0] = (addr >> 8) & 255;
			buf[1] = (addr >> 16) & 255;
			ihex_get_data(addr, block_size, buf + 2);
			write_size = block_size + 2;
		}
		else if (block_size == 512 || block_size == 1024) {
			buf[0] = addr & 255;
			buf[1] = (addr >> 8) & 255;
			buf[2] = (addr >> 16) & 255;
			memset(buf + 3, 0, 61);
			ihex_get_data(addr, block_size, buf + 64);
			write_size = block_size + 64;
		}
		else {
			die("Unknown code/block size\n");
		}
		printf("write size is %d\n", write_size);
		r = teensy_write(buf, write_size, first_block ? 3.0 : 0.1);
		if (!r) die("error writing to Teensy\n");
		first_block = 0;
	}
	printf_verbose("\n");

	// reboot to the user's new code
	if (reboot_after_programming) {
		printf_verbose("Booting\n");
		buf[0] = 0xFF;
		buf[1] = 0xFF;
		buf[2] = 0xFF;
		memset(buf + 3, 0, sizeof(buf) - 3);
		teensy_write(buf, write_size, 0.25);
	}

	Sleep(5000);
	teensy_write("ident", 5, 0.25);

	teensy_close();
	return 0;
}




// http://msdn.microsoft.com/en-us/library/ms790932.aspx
#include <windows.h>
#include <setupapi.h>

extern "C" {
	#include "hidsdi.h"
	#include "hidclass.h"
}



HANDLE open_usb_device(int vid, int pid)
{
	GUID guid;
	HDEVINFO info;
	DWORD index, required_size;
	SP_DEVICE_INTERFACE_DATA iface;
	SP_DEVICE_INTERFACE_DETAIL_DATA *details;
	HIDD_ATTRIBUTES attrib;
	HANDLE h;
	BOOL ret;

	HidD_GetHidGuid(&guid);

	printf_s("%x-%x-%x-", guid.Data1, guid.Data2, guid.Data3);
	for (int i = 0; i < 8; i++) {
		if (i == 2)
			printf_s("-");
		printf_s("%x", guid.Data4[i]);
	}
	printf_s("\n");

	info = SetupDiGetClassDevs(&guid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if (info == INVALID_HANDLE_VALUE) return NULL;
	for (index = 0; 1; index++) {
		iface.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
		ret = SetupDiEnumDeviceInterfaces(info, NULL, &guid, index, &iface);
		if (!ret) {
			printf("no enum %d\n",index);
			SetupDiDestroyDeviceInfoList(info);
			break;
		}
		printf_s("index %d ret %d\n", index,ret);
		SetupDiGetInterfaceDeviceDetail(info, &iface, NULL, 0, &required_size, NULL);
		details = (SP_DEVICE_INTERFACE_DETAIL_DATA *)malloc(required_size);
		if (details == NULL) continue;
		memset(details, 0, required_size);
		details->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
		ret = SetupDiGetDeviceInterfaceDetail(info, &iface, details,
			required_size, NULL, NULL);
		if (!ret) {
			free(details);
			continue;
		}
		h = CreateFile(details->DevicePath, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_FLAG_OVERLAPPED, NULL);
		free(details);
		if (h == INVALID_HANDLE_VALUE) continue;
		attrib.Size = sizeof(HIDD_ATTRIBUTES);
		ret = HidD_GetAttributes(h, &attrib);
		if (!ret) {
			CloseHandle(h);
			continue;
		}
		if (attrib.VendorID != vid || attrib.ProductID != pid) {
			CloseHandle(h);
			continue;
		}
		SetupDiDestroyDeviceInfoList(info);
		return h;
	}
	return NULL;
}

int write_usb_device(HANDLE h, void *buf, int len, int timeout)
{
	static HANDLE event = NULL;
	unsigned char tmpbuf[1089];
	OVERLAPPED ov;
	DWORD n, r;

	if (len > sizeof(tmpbuf) - 1) {
		printf("write error: len > tmpbuf (%d > %d)\n",len,sizeof(tmpbuf));
		return 0;
	}
	if (event == NULL) {
		event = CreateEvent(NULL, TRUE, TRUE, NULL);
		if (!event) {
			printf("write error: could not create event\n");
			return 0;
		}
	}
	ResetEvent(&event);
	memset(&ov, 0, sizeof(ov));
	ov.hEvent = event;
	tmpbuf[0] = 0;
	memcpy(tmpbuf + 1, buf, len);
	if (!WriteFile(h, tmpbuf, len + 1, NULL, &ov)) {
		if (GetLastError() != ERROR_IO_PENDING) {
			printf("write error: no io pending; current code %d\n",GetLastError());
			return 0;
		}
		r = WaitForSingleObject(event, timeout);
		if (r == WAIT_TIMEOUT) {
			CancelIo(h);
			printf("write error: timeout\n");
			return 0;
		}
		if (r != WAIT_OBJECT_0) {
			printf("write error: not wait object\n");
			return 0;
		}
	}
	Sleep(100);
	if (!GetOverlappedResult(h, &ov, &n, FALSE)) {
		printf("write error: overlapped error\n");
		return 0;
	}
	if (n <= 0) {
		printf("write error: n <= 0\n");
		return 0;
	}
	return 1;
}

void print_win32_err(void)
{
	wchar_t buf[256];
	DWORD err;

	err = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
		0, buf, sizeof(buf), NULL);
	printf("err %ld: %s\n", err, buf);
}

static HANDLE win32_teensy_handle = NULL;

int teensy_open(void)
{
	teensy_close();
	win32_teensy_handle = open_usb_device(0x16C0, 0x0478);
	if (win32_teensy_handle) return 1;
	return 0;
}

int teensy_write(void *buf, int len, double timeout)
{
	int r;
	if (!win32_teensy_handle) return 0;
	r = write_usb_device(win32_teensy_handle, buf, len, (int)(timeout * 1000.0));
	//if (!r) print_win32_err();
	return r;
}

void teensy_close(void)
{
	if (!win32_teensy_handle) return;
	CloseHandle(win32_teensy_handle);
	win32_teensy_handle = NULL;
}

int hard_reboot(void)
{
	HANDLE rebootor;
	int r;

	rebootor = open_usb_device(0x16C0, 0x0477);
	if (!rebootor) return 0;
	r = write_usb_device(rebootor, "reboot", 6, 100);
	CloseHandle(rebootor);
	return r;
}

int soft_reboot(void)
{
	printf("Soft reboot is not implemented for Win32\n");
	return 0;
}








/****************************************************************/
/*                                                              */
/*                     Read Intel Hex File                      */
/*                                                              */
/****************************************************************/

// the maximum flash image size we can support
// chips with larger memory may be used, but only this
// much intel-hex data can be loaded into memory!
#define MAX_MEMORY_SIZE 0x20000

static unsigned char firmware_image[MAX_MEMORY_SIZE];
static unsigned char firmware_mask[MAX_MEMORY_SIZE];
static int end_record_seen = 0;
static int byte_count;
static unsigned int extended_addr = 0;
static int parse_hex_line(char *line);

int read_intel_hex(const char *filename)
{
	FILE *fp;
	int i, lineno = 0;
	char buf[1024];

	byte_count = 0;
	end_record_seen = 0;
	for (i = 0; i<MAX_MEMORY_SIZE; i++) {
		firmware_image[i] = 0xFF;
		firmware_mask[i] = 0;
	}
	extended_addr = 0;

	if (fopen_s(&fp,filename, "r")) {
		//printf("Unable to read file %s\n", filename);
		return -1;
	}
	while (!feof(fp)) {
		*buf = '\0';
		if (!fgets(buf, sizeof(buf), fp)) break;
		lineno++;
		if (*buf) {
			if (parse_hex_line(buf) == 0) {
				printf("Warning, HEX parse error line %d\n", lineno);
				return -2;
			}
		}
		if (end_record_seen) break;
		if (feof(stdin)) break;
	}
	fclose(fp);
	return byte_count;
}


/* from ihex.c, at http://www.pjrc.com/tech/8051/pm2_docs/intel-hex.html */

/* parses a line of intel hex code, stores the data in bytes[] */
/* and the beginning address in addr, and returns a 1 if the */
/* line was valid, or a 0 if an error occured.  The variable */
/* num gets the number of bytes that were stored into bytes[] */


int
parse_hex_line(char *line)
{
	int addr, code, num;
	int sum, len, cksum, i;
	char *ptr;

	num = 0;
	if (line[0] != ':') return 0;
	if (strlen(line) < 11) return 0;
	ptr = line + 1;
	if (!sscanf_s(ptr, "%02x", &len)) return 0;
	ptr += 2;
	if ((int)strlen(line) < (11 + (len * 2))) return 0;
	if (!sscanf_s(ptr, "%04x", &addr)) return 0;
	ptr += 4;
	/* printf("Line: length=%d Addr=%d\n", len, addr); */
	if (!sscanf_s(ptr, "%02x", &code)) return 0;
	if (addr + extended_addr + len >= MAX_MEMORY_SIZE) return 0;
	ptr += 2;
	sum = (len & 255) + ((addr >> 8) & 255) + (addr & 255) + (code & 255);
	if (code != 0) {
		if (code == 1) {
			end_record_seen = 1;
			return 1;
		}
		if (code == 2 && len == 2) {
			if (!sscanf_s(ptr, "%04x", &i)) return 1;
			ptr += 4;
			sum += ((i >> 8) & 255) + (i & 255);
			if (!sscanf_s(ptr, "%02x", &cksum)) return 1;
			if (((sum & 255) + (cksum & 255)) & 255) return 1;
			extended_addr = i << 4;
			//printf("ext addr = %05X\n", extended_addr);
		}
		if (code == 4 && len == 2) {
			if (!sscanf_s(ptr, "%04x", &i)) return 1;
			ptr += 4;
			sum += ((i >> 8) & 255) + (i & 255);
			if (!sscanf_s(ptr, "%02x", &cksum)) return 1;
			if (((sum & 255) + (cksum & 255)) & 255) return 1;
			extended_addr = i << 16;
			//printf("ext addr = %08X\n", extended_addr);
		}
		return 1;	// non-data line
	}
	byte_count += len;
	while (num != len) {
		if (sscanf_s(ptr, "%02x", &i) != 1) return 0;
		i &= 255;
		firmware_image[addr + extended_addr + num] = i;
		firmware_mask[addr + extended_addr + num] = 1;
		ptr += 2;
		sum += i;
		(num)++;
		if (num >= 256) return 0;
	}
	if (!sscanf_s(ptr, "%02x", &cksum)) return 0;
	if (((sum & 255) + (cksum & 255)) & 255) return 0; /* checksum error */
	return 1;
}

int ihex_bytes_within_range(int begin, int end)
{
	int i;

	if (begin < 0 || begin >= MAX_MEMORY_SIZE ||
		end < 0 || end >= MAX_MEMORY_SIZE) {
		return 0;
	}
	for (i = begin; i <= end; i++) {
		if (firmware_mask[i]) return 1;
	}
	return 0;
}

void ihex_get_data(int addr, int len, unsigned char *bytes)
{
	int i;

	if (addr < 0 || len < 0 || addr + len >= MAX_MEMORY_SIZE) {
		for (i = 0; i<len; i++) {
			bytes[i] = 255;
		}
		return;
	}
	for (i = 0; i<len; i++) {
		if (firmware_mask[addr]) {
			bytes[i] = firmware_image[addr];
		}
		else {
			bytes[i] = 255;
		}
		addr++;
	}
}

int memory_is_blank(int addr, int block_size)
{
	if (addr < 0 || addr > MAX_MEMORY_SIZE) return 1;

	while (block_size && addr < MAX_MEMORY_SIZE) {
		if (firmware_mask[addr] && firmware_image[addr] != 255) return 0;
		addr++;
		block_size--;
	}
	return 1;
}




/****************************************************************/
/*                                                              */
/*                       Misc Functions                         */
/*                                                              */
/****************************************************************/

int printf_verbose(const char *format, ...)
{
	va_list ap;
	int r;

	va_start(ap, format);
	if (verbose) {
		r = vprintf(format, ap);
		fflush(stdout);
		return r;
	}
	return 0;
}

void delay(double seconds)
{
#ifdef WIN32
	Sleep(seconds * 1000.0);
#else
	usleep(seconds * 1000000.0);
#endif
}

void die(const char *str, ...)
{
	va_list  ap;

	va_start(ap, str);
	vfprintf(stderr, str, ap);
	fprintf(stderr, "\n");
	exit(1);
}

#if defined(WIN32)
#define strcasecmp _stricmp
#endif


static const struct {
	const char *name;
	int code_size;
	int block_size;
} MCUs[] = {
	{ "at90usb162",   15872,   128 },
	{ "atmega32u4",   32256,   128 },
	{ "at90usb646",   64512,   256 },
	{ "at90usb1286", 130048,   256 },
{ "mkl26z64",     63488,   512 },
{ "mk20dx128",   131072,  1024 },
{ "mk20dx256",   262144,  1024 },
{ NULL, 0, 0 },
};


void list_mcus()
{
	int i;
	printf("Supported MCUs are:\n");
	for (i = 0; MCUs[i].name != NULL; i++)
		printf(" - %s\n", MCUs[i].name);
	exit(1);
}


void read_mcu(char *name)
{
	int i;

	if (name == NULL) {
		fprintf(stderr, "No MCU specified.\n");
		list_mcus();
	}

	for (i = 0; MCUs[i].name != NULL; i++) {
		if (strcasecmp(name, MCUs[i].name) == 0) {
			code_size = MCUs[i].code_size;
			block_size = MCUs[i].block_size;
			return;
		}
	}

	fprintf(stderr, "Unknown MCU type \"%s\"\n", name);
	list_mcus();
}


void parse_flag(char *arg)
{
	int i;
	for (i = 1; arg[i]; i++) {
		switch (arg[i]) {
		case 'w': wait_for_device_to_appear = 1; break;
		case 'r': hard_reboot_device = 1; break;
		case 's': soft_reboot_device = 1; break;
		case 'n': reboot_after_programming = 0; break;
		case 'v': verbose = 1; break;
		default:
			fprintf(stderr, "Unknown flag '%c'\n\n", arg[i]);
			usage(NULL);
		}
	}
}


void parse_options(int argc, char **argv)
{
	int i;
	char *arg;

	for (i = 1; i < argc; i++) {
		arg = argv[i];

		//backward compatibility with previous versions.
		if (strncmp(arg, "-mmcu=", 6) == 0) {
			read_mcu(strchr(arg, '=') + 1);
		}

		else if (arg[0] == '-') {
			if (arg[1] == '-') {
				char *name = &arg[2];
				char *val = strchr(name, '=');
				if (val == NULL) {
					//value must be the next string.
					val = argv[++i];
				}
				else {
					//we found an =, so split the string at it.
					*val = '\0';
					val = &val[1];
				}

				if (strcasecmp(name, "help") == 0) usage(NULL);
				else if (strcasecmp(name, "mcu") == 0) read_mcu(val);
				else if (strcasecmp(name, "list-mcus") == 0) list_mcus();
				else {
					fprintf(stderr, "Unknown option \"%s\"\n\n", arg);
					usage(NULL);
				}
			}
			else parse_flag(arg);
		}
		else filename = arg;
	}
}