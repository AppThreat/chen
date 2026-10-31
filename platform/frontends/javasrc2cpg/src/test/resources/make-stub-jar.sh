#!/usr/bin/env bash
# Rebuilds Stub.jar, the test's dependency stub: a chainable type pair, an slf4j
# stand-in, a parameter annotation and Lombok marker annotations, sized in bytes
# and resolved from the classpath like a real dependency. Run from this directory;
# the jar is checked in, so this only matters when the stub changes.
set -euo pipefail
cd "$(dirname "$0")"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat > "$work/FormLogin.java" <<'EOF'
package stub;

public class FormLogin {
    public FormLogin loginPage(String url) { return this; }
    public FormLogin successHandler(Handler handler) { return this; }
}
EOF
cat > "$work/Handler.java" <<'EOF'
package stub;

public interface Handler {
    void handle(String input);
}
EOF
cat > "$work/Security.java" <<'EOF'
package stub;

public class Security {
    public FormLogin formLogin() { return new FormLogin(); }
    public void login(String user) {}
    public Security self() { return this; }
    public static Security http() { return new Security(); }
    public static final String VERSION = "1.0";
}
EOF
cat > "$work/RequestParam.java" <<'EOF'
package stub;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER, ElementType.METHOD})
public @interface RequestParam {
    String value() default "";
    boolean required() default true;
}
EOF
cat > "$work/Logger.java" <<'EOF'
package org.slf4j;

public interface Logger {
    void info(String message);
    void warn(String message);
    void error(String message);
}
EOF
cat > "$work/LoggerFactory.java" <<'EOF'
package org.slf4j;

public class LoggerFactory {
    public static Logger getLogger(Class<?> clazz) { return null; }
}
EOF
cat > "$work/Slf4j.java" <<'EOF'
package lombok.extern.slf4j;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
public @interface Slf4j {
}
EOF
cat > "$work/Getter.java" <<'EOF'
package lombok;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.SOURCE)
@Target({ElementType.TYPE, ElementType.FIELD})
public @interface Getter {
}
EOF
cat > "$work/Data.java" <<'EOF'
package lombok;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
public @interface Data {
}
EOF

classes="$work/classes"
mkdir -p "$classes"
javac -d "$classes" "$work"/*.java
jar cf Stub.jar -C "$classes" .
echo "rebuilt Stub.jar"
