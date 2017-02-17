# tcpsnitch for Android

This folder contains several helper bash scripts to deal with Android devices.

## Compilation

tcpsnitch has been sucessfully compiled with the NDK for Android API 23.

Just issue `make` from here to compile the Android version (or `make android` from the root diretory).
Before that, you must adjust the `CC_ANDROID` variable in the root Makefile to point to the NDK compiler.

## Helper scripts

Most scripts available in this directory accept a single argument which should match a package installed on the Android device via a simple `grep`. In case of multiple matches, the first matched package will be used.

For instance, run `setup_app air` would match the `com.airbnb.android` package.

You need to install `busybox` on the device.
