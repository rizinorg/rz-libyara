project('rz_yara', 'c', meson_version: '>=0.55.0')

cc = meson.get_compiler('c')
rz_core_dep = dependency('rz_core')

common_c_args = []
rz_yara_c_args = []

rz_yara_deps = [
  rz_core_dep,
  dependency('threads', required: false),
  cc.find_library('m', required: false),
]

# handle yara library
sys_yara_opt = get_option('use_sys_yara')
yara_dep = disabler()
if sys_yara_opt.enabled() or sys_yara_opt.auto()
  yara_dep = dependency('yara', required: false)
  if not yara_dep.found()
    yara_dep = cc.find_library('yara', required: sys_yara_opt)
  endif
endif
if (sys_yara_opt.auto() and not yara_dep.found()) or sys_yara_opt.disabled()
  yara_proj = subproject('yara', default_options: ['default_library=static'])
  yara_dep = yara_proj.get_variable('yara_dep')
endif

rz_yara_deps += yara_dep

rz_yara_incs = [
  'include',
  'src',
]

rz_yara_src = [
  'src/yara_parser.c',
  'src/yara_generator.c',
  'src/yara_plugin.c',
]

rizin_plugdir = get_option('rizin_plugdir')
if rizin_plugdir == ''
  rizin_plugdir = rz_core_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')
endif

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
