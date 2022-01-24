# Rizin libyara plugin & library wrapper

Rizin libyara wrapper for creating, parsing and applying YARA rules.

# Install system wide plugin folder

```
meson build
ninja -C build
ninja -C build install
```

or on a custom location

```
meson --prefix=/usr build
ninja -C build
ninja -C build install
```

# Install in home plugin folder

```
meson --prefix=~/.local build
ninja -C build
ninja -C build install
```

## Build ASAN

```
meson -Dbuildtype=debugoptimized -Db_sanitize=address,undefined build
ninja -C build
```
