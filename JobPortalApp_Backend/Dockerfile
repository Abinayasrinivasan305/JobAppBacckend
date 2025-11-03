# Use official Maven with JDK
FROM maven:3.9.6-eclipse-temurin-17

WORKDIR /app

# Copy all files
COPY . .

# Grant permission to mvnw
RUN chmod +x mvnw

# Build the jar file inside container
RUN ./mvnw clean package -DskipTests

# Expose backend port
EXPOSE 8080

# Run the jar
CMD ["java", "-jar", "target/jobappbackend.jar"]
