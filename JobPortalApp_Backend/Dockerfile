# Step 1: Use official Java runtime as base image
FROM openjdk:17-jdk-slim

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Copy the jar file into the container
COPY target/jobappbackend.jar app.jar

# Step 4: Expose port 8080 (the port your Spring Boot app runs on)
EXPOSE 8080

# Step 5: Run the jar file
ENTRYPOINT ["java", "-jar", "app.jar"]
