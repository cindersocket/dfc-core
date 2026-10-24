-keepclasseswithmembernames class * {
    native <methods>;
}

# Native failures resolve this class and constructor by their binary names.
-keep,allowoptimization class com.cindersocket.dfc.DfcException {
    public <init>(java.lang.String, int, int, int);
}
