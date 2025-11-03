# Use Java 21 image to match your local build
FROM openjdk:21-jdk-slim

WORKDIR /app

# Copy the JAR file
COPY JobPortalApp_Backend/target/JobPortalApp_Backend-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
