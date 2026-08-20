import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.withGroovyBuilder

group = "bt4pt"
version = "0.1-SNAPSHOT"

buildscript {
    repositories {
        mavenCentral()
        maven(url = "https://javacard.pro/maven")
        maven(url = "https://deadcode.me/mvn")
        // mavenLocal()
    }

    dependencies {
        classpath("com.klinec:gradle-javacard:1.8.0")
    }
}

plugins {
    application
    idea
}

apply(plugin = "com.klinec.gradle.javacard")

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
}

val rootPath = rootDir.absolutePath
val libs = "$rootPath/libs"
val libsSdk = "$rootPath/libs-sdks"

repositories {
    mavenCentral()
    // mavenLocal()

    maven(url = "https://javacard.pro/maven")
    maven(url = "https://deadcode.me/mvn")

//    flatDir {
//        dirs(libs)
//    }
}

sourceSets {
    main {
        java.srcDir("src/javacard/java")
    }
}

dependencies {
    add("jcardsim", "com.klinec:jcardsim:3.0.5.11")

    implementation("com.klinec:jcardsim:3.0.5.11")

    testImplementation("org.testng:testng:6.1.1")
    testImplementation("org.slf4j:slf4j-api:1.7.33")
    testImplementation("org.slf4j:slf4j-log4j12:1.7.33")
    testImplementation("org.apache.logging.log4j:log4j-core:2.25.4")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.1.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.1.1")

    testImplementation("com.klinec:javacard-tools:1.0.4") {
        exclude(group = "com.klinec", module = "jcardsim")
    }

    runtimeOnly("com.klinec:gradle-javacard:1.8.0")
}

tasks.register("dumpClassPath") {
    dependsOn("idea")

    doLast {
        val gradleClasspath = configurations
            .getByName("compileClasspath")
            .files
            .joinToString("\n- ") { it.name }

        val ideaClasspath = file("${project.name}.iml")
            .readLines()
            .filter { it.matches(Regex(""".*"jar:.*""")) }
            .map { line ->
                val parts = line.split(Regex("""[\\/]"""))
                parts[parts.size - 3].trim()
            }
            .joinToString("\n- ")

        println("Gradle classpath:\n- $gradleClasspath")
        println("-------\n")
        println("IDEA classpath:\n- $ideaClasspath")
        println("-------\n")
    }
}

application {
    mainClass.set("net.as207960.bt4pt.hsm.main.Run")
}

tasks.test {
    useJUnitPlatform {
        excludeTags("manual")
    }
}

val manualTests by tasks.registering(Test::class) {
    useJUnitPlatform {
        includeTags("manual")
    }

    shouldRunAfter(tasks.test)
}

tasks.check {
    dependsOn(manualTests)
}

// JavaCard SDKs and libraries
val JC212 = "$libsSdk/jc212_kit"
val JC221 = "$libsSdk/jc221_kit"
val JC222 = "$libsSdk/jc222_kit"
val JC303 = "$libsSdk/jc303_kit"
val JC304 = "$libsSdk/jc304_kit"
val JC305 = "$libsSdk/jc305u1_kit"
val JC305u2 = "$libsSdk/jc305u2_kit"
val JC305u3 = "$libsSdk/jc305u3_kit"
val JC310b43 = "$libsSdk/jc310b43_kit"

// Which JavaCard SDK to use
val JC_SELECTED = JC310b43

extensions.getByName("javacard").withGroovyBuilder {
    "config" {
        "jckit"(JC_SELECTED)

        "debugGpPro"(true)
        "addImplicitJcardSim"(false)
        "addImplicitJcardSimJunit"(false)

        "cap" {
            "packageName"("net.as207960.bt4pt.hsm.applet")
            "version"("0.1")
            "aid"("E8:2B:06:01:04:01:83:B7:64:03:01")
            "output"("applet.cap")
            "sources"(file("src/javacard/java").absolutePath)

            "targetsdk"(JC305)
            "ints"(true)

            // "javaversion"("1.7")

            "applet" {
                "className"("net.as207960.bt4pt.hsm.applet.MainApplet")
                "aid"("E8:2B:06:01:04:01:83:B7:64:03:01:00")
            }

            // "dependencies" {
            //     "remote"("com.klinec:globalplatform:2.1.1")
            // }
        }
    }
}
