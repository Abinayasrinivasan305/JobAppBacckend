# ✅ Use modern, stable JDK 21 image (official Temurin build)
FROM eclipse-temurin:21-jdk-jammy

WORKDIR /app

# Copy the built JAR file from your project
COPY JobPortalApp_Backend/target/JobPortalApp_Backend-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

# Run the JAR file
ENTRYPOINT ["java", "-jar", "app.jar"]
