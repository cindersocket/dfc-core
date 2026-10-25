# Error Prone annotations are compile-time metadata. Their own annotation metadata
# references the JDK compiler model, which Android intentionally does not ship.
-dontwarn javax.lang.model.element.Modifier
