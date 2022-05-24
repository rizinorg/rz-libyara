cmake_minimum_required(VERSION 3.12)
project(cutter-yara-plugin)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CUTTER_INSTALL_PLUGDIR "share/rizin/cutter/plugins/native" CACHE STRING "Directory to install Cutter plugin into")
set(RIZIN_INSTALL_PLUGDIR "lib/rizin/plugins" CACHE STRING "Directory where to find librz_yara")
set(CUTTER_SOURCE_DIR CUTTER_SOURCE_DIR-NOTFOUND CACHE STRING "Root directory of Cutter source")
option(CUTTER_QT6 "Use QT6" OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(QT_COMPONENTS Core Widgets Gui Svg Network)
if (CUTTER_QT6)
    set(QT_PREFIX Qt6)
    list(APPEND QT_COMPONENTS Core5Compat SvgWidgets OpenGLWidgets)
else()
    set(QT_PREFIX Qt5)
endif()
find_package(${QT_PREFIX} REQUIRED COMPONENTS ${QT_COMPONENTS})

add_library(cutter_yara_plugin MODULE
    YaraAddDialog.cpp
    YaraAddDialog.h
    YaraAddDialog.ui
    YaraAddMetaDialog.cpp
    YaraAddMetaDialog.h
    YaraAddMetaDialog.ui
    YaraDescription.h
    YaraPlugin.cpp
    YaraPlugin.h
    YaraSyntax.cpp
    YaraSyntax.h
    YaraTextEditor.cpp
    YaraTextEditor.h
    YaraTextEditor.ui
    YaraViewMenu.cpp
    YaraViewMenu.h
    YaraWidget.cpp
    YaraWidget.h
    YaraWidget.ui
)

find_library(RzYara NAMES rz_yara PATHS "${RIZIN_INSTALL_PLUGDIR}")
include_directories("../include")

find_package(Cutter REQUIRED)
target_link_libraries(cutter_yara_plugin PRIVATE Cutter::Cutter "${RzYara}")
install(TARGETS cutter_yara_plugin DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
