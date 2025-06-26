# 1. Pulling the dependencies
FROM maven:3.8.5-openjdk-17 AS builder
# Change working directory in the container
WORKDIR /opt/app
# Copy all POMs first for better build caching
COPY ../pom.xml .
COPY ../authorization_server/pom.xml ./authorization_server/pom.xml
COPY ../resource_server/pom.xml ./resource_server/pom.xml
COPY ../common_tools/pom.xml ./common_tools/pom.xml

# Copy source code
COPY ../authorization_server/src ./authorization_server/src
COPY ../resource_server/src ./resource_server/src
COPY ../common_tools/src ./common_tools/src

# compile code in /opt/app
RUN mvn -B -e clean install -DskipTests

# 3. Preparing the runtime environment
FROM openjdk:17-slim

WORKDIR /opt/app

# Start resource_server
COPY --from=builder /opt/app/resource_server/target/*.jar /resource_server.jar
EXPOSE 8085
ENTRYPOINT ["java", "-jar", "/resource_server.jar"]
