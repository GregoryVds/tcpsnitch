# tcpsnitch for Android

This folder contains several helper bash scripts to deal with Android devices.

## Compilation

tcpsnitch has been sucessfully compiled with the NDK for Android API 23.

You must set the `CC_ANDROID`, pointing the the Android NDK compiler, before issuing make.

## Helper scripts

Most scripts available in this directory accept a single argument which should match a package installed on the Android device via a simple `grep`. In case of multiple matches, the first matched package will be used.

For instance, run `setup_app air` would match the `com.airbnb.android` package.

You need to install `busybox` on the device.
