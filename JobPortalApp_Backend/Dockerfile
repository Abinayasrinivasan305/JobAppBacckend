# Use lightweight JDK 17 image
FROM openjdk:17-jdk-slim

# Set working directory
WORKDIR /app

# Copy only the jar from the target folder
COPY target/jobappbackend.jar app.jar

# Expose port
EXPOSE 8080

# Run the JAR
ENTRYPOINT ["java", "-jar", "app.jar"]
