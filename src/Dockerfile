# 1st Docker build stage: build the project with Maven
FROM maven:3.9.3 AS builder
WORKDIR /peer-peer-messaging
COPY . /peer-peer-messaging/
RUN mvn clean package -DskipTests -e

# 2nd Docker build stage: copy builder output and configure entry point
FROM eclipse-temurin:17-jre
ENV APP_DIR /application
ENV APP_FILE peer-peer-messaging-jar.jar

EXPOSE 8080

WORKDIR $APP_DIR
COPY --from=builder /peer-peer-messaging/target/*.jar $APP_DIR/$APP_FILE

ENTRYPOINT ["sh", "-c","java $JAVA_OPTS -jar $APP_FILE"]
