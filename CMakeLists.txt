cmake_minimum_required(VERSION 3.5)

project(myWireshark VERSION 0.1 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets LinguistTools REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets LinguistTools REQUIRED)

set(TS_FILES myWireshark_zh_CN.ts)

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
#        ${TS_FILES}
        resources.qrc
        commonDebug.h
        mypcap.h
        mypcap.cpp
        Format.h
        datapackage.h
        datapackage.cpp
        readonlydelegate.h
        readonlydelegate.cpp
)

##################### my add start ##########################
set(PROJECT_DIR         ${PROJECT_SOURCE_DIR})
set(THIRDPARTY_DIR      ${PROJECT_DIR}/thirdparty)
include_directories(
    ${THIRDPARTY_DIR}/npcap-sdk-1.11/Include
)
link_directories(
    ${THIRDPARTY_DIR}/npcap-sdk-1.11/Lib/x64
)
##################### my add end ############################

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(myWireshark
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET myWireshark APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation

    qt_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
else()
    if(ANDROID)
        add_library(myWireshark SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(myWireshark
            ${PROJECT_SOURCES}
        )
    endif()

    qt5_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
endif()

##################### my add start ##########################
target_link_libraries(myWireshark PRIVATE Packet wpcap ws2_32)

##################### my add end ############################

target_link_libraries(myWireshark PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

set_target_properties(myWireshark PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(myWireshark)
endif()
