[app]
title = AquaSecure Pro
package.name = aquasecurepro
package.domain = com.aquasecure
version = 1.0.0
source.dir = .
source.include_exts = py,png,jpg,jpeg,kv,ttf,otf
requirements = python3,kivy==2.1.0,Pillow==9.0.0,qrcode==7.4.2,cryptography==38.0.0
android.permissions = INTERNET,ACCESS_FINE_LOCATION,ACCESS_COARSE_LOCATION,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CAMERA,RECORD_AUDIO,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE
android.api = 31
android.minapi = 24
android.sdk = 33
android.ndk = 25b
android.gradle_dependencies = 'com.google.android.gms:play-services-location:21.0.1'
android.arch = arm64-v8a,armeabi-v7a
orientation = portrait
fullscreen = 0
log_level = 2
wake_lock = True
android.allow_backup = True