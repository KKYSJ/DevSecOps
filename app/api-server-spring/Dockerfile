FROM eclipse-temurin:21-jdk-alpine AS build

WORKDIR /workspace

COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN chmod +x mvnw

COPY src src
RUN ./mvnw -q -DskipTests package

FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

RUN apk add --no-cache curl

COPY --from=build /workspace/target/*.jar app.jar

RUN mkdir -p /app/data /app/uploads

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD sh -c 'curl -fsS "http://127.0.0.1:${SERVER_PORT:-8080}${APP_API_BASE_PATH:-/api}/health" >/dev/null || exit 1'

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
