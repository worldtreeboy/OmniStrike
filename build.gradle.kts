plugins {
    java
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.portswigger.burp.extensions:montoya-api:2026.2")
    implementation("com.google.code.gson:gson:2.11.0")
    // Gadget chain libraries (needed to construct real serialized objects)
    implementation("commons-collections:commons-collections:3.1")
    implementation("org.apache.commons:commons-collections4:4.0")
    implementation("commons-beanutils:commons-beanutils:1.9.2")
    implementation("org.javassist:javassist:3.29.2-GA")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.shadowJar {
    archiveBaseName.set("omnistrike")
    archiveClassifier.set("")
    archiveVersion.set("")
}
