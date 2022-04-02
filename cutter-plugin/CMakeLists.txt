cmake_minimum_required(VERSION 3.12)
project(cutter-yara-plugin)

set(CUTTER_INSTALL_PLUGDIR "share/rizin/cutter/plugins/native" CACHE STRING "Directory to install Cutter plugin into")
set(RIZIN_INSTALL_PLUGDIR "lib/rizin/plugins" CACHE STRING "Directory where to find librz_yara")

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)

add_library(cutter_yara_plugin MODULE
    ../include/rz_yara.h
    YaraWidget.ui
    YaraAddMetaDialog.ui
    YaraAddDialog.ui
    YaraPlugin.h
    YaraPlugin.cpp
    YaraViewMenu.cpp
    YaraWidget.cpp
    YaraAddMetaDialog.cpp
    YaraSyntax.cpp
    YaraAddDialog.cpp
    YaraViewMenu.h
    YaraWidget.h
    YaraAddMetaDialog.h
    YaraSyntax.h
    YaraAddDialog.h
    YaraDescription.h
)

find_library(RzYara NAMES rz_yara HINTS "${RIZIN_INSTALL_PLUGDIR}")
find_package(Cutter REQUIRED)
target_link_libraries(cutter_yara_plugin PRIVATE Cutter::Cutter "${RzYara}")
install(TARGETS cutter_yara_plugin DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
