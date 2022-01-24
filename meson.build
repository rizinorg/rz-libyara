project('rz_yara', 'c', meson_version: '>=0.51.0')

cc = meson.get_compiler('c')
rz_core_dep = dependency('rz_core')

common_c_args = []
rz_yara_c_args = [
 '-DMACHO_MODULE=1',
 '-DDEX_MODULE=1',
 '-DDOTNET_MODULE=1',
 '-DDEX_MODULE=1',
]

rz_yara_deps = [
  rz_core_dep,
  dependency('threads', required: false),
  cc.find_library('m', required: false),
]

rz_yara_incs = [
  'include',
  'src',
  'yara' / 'libyara',
  'yara' / 'libyara' / 'include',
]

rz_yara_src = [
  'src/yara_parser.c',
  'src/yara_generator.c',
  'src/yara_plugin.c',

  'yara/libyara/ahocorasick.c',
  'yara/libyara/arena.c',
  'yara/libyara/atoms.c',
  'yara/libyara/base64.c',
  'yara/libyara/bitmask.c',
  'yara/libyara/compiler.c',
  'yara/libyara/endian.c',
  'yara/libyara/exec.c',
  'yara/libyara/exefiles.c',
  'yara/libyara/filemap.c',
  'yara/libyara/grammar.c',
  'yara/libyara/hash.c',
  'yara/libyara/hex_grammar.c',
  'yara/libyara/hex_lexer.c',
  'yara/libyara/lexer.c',
  'yara/libyara/libyara.c',
  'yara/libyara/mem.c',
  'yara/libyara/modules.c',
  #'yara/libyara/modules/cuckoo/cuckoo.c',
  'yara/libyara/modules/dex/dex.c',
  'yara/libyara/modules/dotnet/dotnet.c',
  'yara/libyara/modules/elf/elf.c',
  'yara/libyara/modules/macho/macho.c',
  #'yara/libyara/modules/magic/magic.c',
  'yara/libyara/modules/math/math.c',
  'yara/libyara/modules/pe/pe.c',
  'yara/libyara/modules/pe/pe_utils.c',
  'yara/libyara/modules/tests/tests.c',
  'yara/libyara/modules/time/time.c',
  'yara/libyara/notebook.c',
  'yara/libyara/object.c',
  'yara/libyara/parser.c',
  'yara/libyara/proc.c',
  'yara/libyara/re.c',
  'yara/libyara/re_grammar.c',
  'yara/libyara/re_lexer.c',
  'yara/libyara/rules.c',
  'yara/libyara/scan.c',
  'yara/libyara/scanner.c',
  'yara/libyara/sizedstr.c',
  'yara/libyara/stack.c',
  'yara/libyara/stopwatch.c',
  'yara/libyara/stream.c',
  'yara/libyara/strutils.c',
  'yara/libyara/threading.c',
]

if host_machine.system() == 'openbsd'
  rz_yara_src += 'yara/libyara/proc/openbsd.c'
  rz_yara_c_args += '-DUSE_OPENBSD_PROC'
elif host_machine.system() == 'windows'
  rz_yara_src += 'yara/libyara/proc/windows.c'
  rz_yara_c_args += '-DUSE_WINDOWS_PROC'
elif host_machine.system() == 'freebsd'
  rz_yara_src += 'yara/libyara/proc/freebsd.c'
  rz_yara_c_args += '-DUSE_FREEBSD_PROC'
elif host_machine.system() == 'darwin'
  rz_yara_src += 'yara/libyara/proc/mach.c'
  rz_yara_c_args += '-DUSE_MACH_PROC'
elif host_machine.system() == 'linux' or host_machine.system() == 'dragonfly' or host_machine.system() == 'netbsd'
  rz_yara_src += 'yara/libyara/proc/linux.c'
  rz_yara_c_args += '-DUSE_LINUX_PROC'
else
  rz_yara_src += 'yara/libyara/proc/none.c'
  rz_yara_c_args += '-DUSE_NO_PROC'
endif

openssl = dependency('openssl', required: false)
if openssl.found()
  rz_yara_deps += dependency('openssl', required: true)
  rz_yara_c_args += '-DHASH_MODULE=1'
  rz_yara_c_args += '-DHAVE_LIBCRYPTO=1'
  rz_yara_c_args += '-DHAVE_OPENSSL_ASN1_H=1'
  rz_yara_c_args += '-DHAVE_OPENSSL_BIO_H=1'
  rz_yara_c_args += '-DHAVE_OPENSSL_CRYPTO_H=1'
  rz_yara_c_args += '-DHAVE_OPENSSL_MD5_H=1'
  rz_yara_c_args += '-DHAVE_OPENSSL_PKCS7_H=1'
  rz_yara_c_args += '-DHAVE_OPENSSL_SHA_H=1'
  rz_yara_c_args += '-DHAVE_OPENSSL_X509_H=1'
  rz_yara_src += 'yara/libyara/modules/hash/hash.c'
endif

tests = [
  'yara',
]

rizin_plugdir = get_option('rizin_plugdir')
if rizin_plugdir == ''
  rizin_plugdir = rz_core_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')
endif

#if cc.has_argument('-std=gnu89')
#  add_project_arguments('-std=gnu89', language: ['c'])
#elif cc.has_argument('-std=c89')
#  add_project_arguments('-std=c89', language: ['c'])
#endif

if cc.has_argument('-fPIC')
  add_project_arguments('-fPIC', language: ['c'])
endif

rz_yara_lib = shared_library('rz_yara', rz_yara_src,
  c_args : common_c_args + rz_yara_c_args,
  dependencies: rz_yara_deps,
  implicit_include_directories: false,
  install: true,
  install_dir: rizin_plugdir,
  include_directories: include_directories(rz_yara_incs)
)

rz_yara_dep = declare_dependency(
  link_with: rz_yara_lib,
  dependencies: rz_yara_deps,
  include_directories: include_directories('include'),
)
