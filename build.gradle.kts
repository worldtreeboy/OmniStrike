plugins {
    java
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

repositories {
    mavenCentral()
}

dependencies {
    // Montoya API is provided by Burp at runtime — compile against it but DON'T
    // bundle it. Shadow-bundling it is dead weight (Burp's classloader wins by
    // parent-first delegation) and risks class-identity conflicts.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.2")

    // OmniStrike's own JSON usage — relocated in the shadowJar block below so it
    // can't clash with a different Gson bundled by Burp or another extension.
    implementation("com.google.code.gson:gson:2.11.0")

    // Gadget chain libraries — needed to CONSTRUCT real serialized payloads.
    // IMPORTANT: these are NOT relocated and the jar is NOT minimized. The
    // serialized objects we emit must carry the gadget classes' real package
    // names (e.g. org.apache.commons.collections.functors.InvokerTransformer)
    // because those names have to match the *victim's* classpath, and
    // DeserializationScanner also resolves them via Class.forName(<real name>).
    // Relocating would rewrite those names; minimizing would strip the
    // reflectively-loaded classes — either one breaks every deser payload.
    implementation("commons-collections:commons-collections:3.1")
    implementation("org.apache.commons:commons-collections4:4.0")
    implementation("commons-beanutils:commons-beanutils:1.9.2")
    implementation("org.javassist:javassist:3.29.2-GA")
    implementation("rome:rome:1.0")
    implementation("org.codehaus.groovy:groovy:2.3.9")
    implementation("org.beanshell:bsh:2.0b5")
    implementation("com.mchange:c3p0:0.9.5.2")

    // Unit tests (JUnit 5).
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    // Montoya is compileOnly above, so tests that touch it need it explicitly.
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.2")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveBaseName.set("omnistrike")
    archiveClassifier.set("")
    archiveVersion.set("")

    // Isolate our Gson so it never collides with another Gson on Burp's
    // classpath. Shadow rewrites OmniStrike's own references to match.
    // Deliberately no minimize() and no relocate of the gadget-chain libs —
    // see the dependency comment above.
    relocate("com.google.gson", "omnistrike.shaded.gson")
}
