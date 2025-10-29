export SPRING_PROFILES_ACTIVE=dev
mvn clean install
nohup java -jar authorization_server/target/authorization_server-0.0.1-SNAPSHOT.jar --spring.config.additional-location=config_files/application-secret.yml > nohup_AS.out 2>&1 &