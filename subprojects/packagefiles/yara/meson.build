project('yara', 'c', meson_version: '>=0.55.0')

cc = meson.get_compiler('c')

yara_deps = [
  dependency('threads', required: false),
  cc.find_library('m', required: false),
]

yara_c_args = [
 '-DMACHO_MODULE=1',
 '-DDEX_MODULE=1',
 '-DDOTNET_MODULE=1',
 '-DDEX_MODULE=1',
]

yara_src = [
  'libyara/ahocorasick.c',
  'libyara/arena.c',
  'libyara/atoms.c',
  'libyara/base64.c',
  'libyara/bitmask.c',
  'libyara/compiler.c',
  'libyara/endian.c',
  'libyara/exec.c',
  'libyara/exefiles.c',
  'libyara/filemap.c',
  'libyara/grammar.c',
  'libyara/hash.c',
  'libyara/hex_grammar.c',
  'libyara/hex_lexer.c',
  'libyara/lexer.c',
  'libyara/libyara.c',
  'libyara/mem.c',
  'libyara/modules.c',
  #'libyara/modules/cuckoo/cuckoo.c',
  'libyara/modules/dex/dex.c',
  'libyara/modules/dotnet/dotnet.c',
  'libyara/modules/elf/elf.c',
  'libyara/modules/macho/macho.c',
  #'libyara/modules/magic/magic.c',
  'libyara/modules/math/math.c',
  'libyara/modules/pe/pe.c',
  'libyara/modules/pe/pe_utils.c',
  'libyara/modules/tests/tests.c',
  'libyara/modules/time/time.c',
  'libyara/notebook.c',
  'libyara/object.c',
  'libyara/parser.c',
  'libyara/proc.c',
  'libyara/re.c',
  'libyara/re_grammar.c',
  'libyara/re_lexer.c',
  'libyara/rules.c',
  'libyara/scan.c',
  'libyara/scanner.c',
  'libyara/sizedstr.c',
  'libyara/stack.c',
  'libyara/stopwatch.c',
  'libyara/stream.c',
  'libyara/strutils.c',
  'libyara/threading.c',
]

if host_machine.system() == 'openbsd'
  yara_src += 'libyara/proc/openbsd.c'
  yara_c_args += '-DUSE_OPENBSD_PROC'
elif host_machine.system() == 'windows'
  yara_src += 'libyara/proc/windows.c'
  yara_c_args += '-DUSE_WINDOWS_PROC'
elif host_machine.system() == 'freebsd'
  yara_src += 'libyara/proc/freebsd.c'
  yara_c_args += '-DUSE_FREEBSD_PROC'
elif host_machine.system() == 'darwin'
  yara_src += 'libyara/proc/mach.c'
  yara_c_args += '-DUSE_MACH_PROC'
elif host_machine.system() == 'linux' or host_machine.system() == 'dragonfly' or host_machine.system() == 'netbsd'
  yara_src += 'libyara/proc/linux.c'
  yara_c_args += '-DUSE_LINUX_PROC'
else
  yara_src += 'libyara/proc/none.c'
  yara_c_args += '-DUSE_NO_PROC'
endif

if get_option('enable_openssl')
  openssl = dependency('openssl', required: false)
  if openssl.found()
    yara_deps += openssl
    yara_c_args += '-DHASH_MODULE=1'
    yara_c_args += '-DHAVE_LIBCRYPTO=1'
    yara_c_args += '-DHAVE_OPENSSL_ASN1_H=1'
    yara_c_args += '-DHAVE_OPENSSL_BIO_H=1'
    yara_c_args += '-DHAVE_OPENSSL_CRYPTO_H=1'
    yara_c_args += '-DHAVE_OPENSSL_MD5_H=1'
    yara_c_args += '-DHAVE_OPENSSL_PKCS7_H=1'
    yara_c_args += '-DHAVE_OPENSSL_SHA_H=1'
    yara_c_args += '-DHAVE_OPENSSL_X509_H=1'
    yara_src += 'libyara/modules/hash/hash.c'
  endif
endif

yara_incs = [
  'libyara',
  'libyara' / 'include',
]

if cc.has_argument('-fPIC')
  add_project_arguments('-fPIC', language: ['c'])
endif

yara_lib = static_library('yara', yara_src,
  c_args : yara_c_args,
  dependencies: yara_deps,
  implicit_include_directories: false,
  install: false,
  include_directories: include_directories(yara_incs)
)

yara_dep = declare_dependency(
  link_with: yara_lib,
  dependencies: yara_deps,
  include_directories: include_directories(yara_incs),
)
