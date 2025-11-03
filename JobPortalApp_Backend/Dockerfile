# Use official JDK 17 image
FROM openjdk:17-jdk-slim

# Set working directory inside container
WORKDIR /app

# Copy Maven project files and build it
COPY . .

# Build the jar file inside container
RUN ./mvnw clean package -DskipTests

# Expose backend port
EXPOSE 8080

# Run the generated jar file
ENTRYPOINT ["java", "-jar", "target/jobappbackend.jar"]
