# Dockerfile for Spring Boot application
FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app
COPY . .

RUN mvn clean package -DskipTests

# Run the application using JDK 17
FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]

# Expose port 8080
EXPOSE 8080
