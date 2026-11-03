# JNA and the generated UniFFI bindings are reached via reflection/JNI.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-dontwarn java.awt.**
-keep class link.yggdrasil.embed.** { *; }
