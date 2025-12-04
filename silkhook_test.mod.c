#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

KSYMTAB_FUNC(silkhook_ksym, "", "");
KSYMTAB_FUNC(silkhook_ksym_mod, "", "");

SYMBOL_CRC(silkhook_ksym, 0x235c48f8, "");
SYMBOL_CRC(silkhook_ksym_mod, 0x6a6e570b, "");

static const char ____versions[]
__used __section("__versions") =
	"\x1c\x00\x00\x00\x9d\xa6\xe1\xa6"
	"kick_all_cpus_sync\0\0"
	"\x14\x00\x00\x00\x6e\x4a\x6e\x65"
	"snprintf\0\0\0\0"
	"\x10\x00\x00\x00\x7e\xa4\x29\x48"
	"memcpy\0\0"
	"\x18\x00\x00\x00\x8c\x89\xd4\xcb"
	"fortify_panic\0\0\0"
	"\x10\x00\x00\x00\x7e\x3a\x2c\x12"
	"_printk\0"
	"\x1c\x00\x00\x00\xcb\xf6\xfd\xf0"
	"__stack_chk_fail\0\0\0\0"
	"\x10\x00\x00\x00\xad\x64\xb7\xdc"
	"memset\0\0"
	"\x14\x00\x00\x00\xe3\x6f\xab\x88"
	"kgdb_active\0"
	"\x14\x00\x00\x00\xb4\xf7\x2a\x7a"
	"cpu_number\0\0"
	"\x10\x00\x00\x00\x97\x82\x9e\x99"
	"vfree\0\0\0"
	"\x20\x00\x00\x00\xab\x68\xe1\xc2"
	"caches_clean_inval_pou\0\0"
	"\x18\x00\x00\x00\x3b\xcf\x72\x04"
	"register_kprobe\0"
	"\x1c\x00\x00\x00\xed\xb1\x78\xeb"
	"unregister_kprobe\0\0\0"
	"\x2c\x00\x00\x00\xc6\xfa\xb1\x54"
	"__ubsan_handle_load_invalid_value\0\0\0"
	"\x18\x00\x00\x00\xd4\xce\x9f\xb7"
	"module_layout\0\0\0"
	"\x00\x00\x00\x00\x00\x00\x00\x00";

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "7EDEF865CD1153F8A60BF53");
