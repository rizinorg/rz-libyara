# Rizin/Cutter libyara plugin & library wrapper

Rizin libyara wrapper for creating, parsing and applying YARA rules and Cutter native plugin.

# Screenshots

![Screenshot1](https://raw.githubusercontent.com/rizinorg/rz-libyara/main/.images/rizin.png)
![Screenshot2](https://raw.githubusercontent.com/rizinorg/rz-libyara/main/.images/cutter.png)
![Screenshot3](https://raw.githubusercontent.com/rizinorg/rz-libyara/main/.images/rule.png)

# Rizin Plugin
## Install system wide plugin folder

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

## Install in home plugin folder

```
meson --prefix=~/.local build
ninja -C build
ninja -C build install
```

### Build ASAN

```
meson -Dbuildtype=debugoptimized -Db_sanitize=address,undefined build
ninja -C build
```

# Cutter Plugin

- Requires to install all cutter headers to build the plugin

```
mkdir build
cd build
cmake ..
make
make install
```
