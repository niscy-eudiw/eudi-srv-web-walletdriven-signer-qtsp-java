export SPRING_PROFILES_ACTIVE=dev
mvn clean install
java -jar authorization_server/target/authorization_server-0.0.1-SNAPSHOT.jar --spring.config.additional-location=config_files/application-secret.yml