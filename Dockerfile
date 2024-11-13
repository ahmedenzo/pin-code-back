# Stage 1: Build the application using Maven (JDK 17 & Maven are assumed to be installed)
FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app

# Copy the source code into the image
COPY . .

# Run Maven build to generate the jar file, skipping tests
RUN mvn clean package -DskipTests

# Stage 2: Run the application using OpenJDK 17 (JDK 17 already installed)
FROM openjdk:17-jdk-slim

# Set the working directory in the second image
WORKDIR /app

# Copy the jar file from the build stage
COPY --from=build /app/target/*.jar app.jar

# Expose port 8080 to allow external access
EXPOSE 8080

# Set the entry point to run the jar file using Java
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
