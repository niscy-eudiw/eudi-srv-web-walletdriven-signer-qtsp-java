export SPRING_PROFILES_ACTIVE=noauth
nohup java -jar resource_server/target/resource_server-0.0.1-SNAPSHOT.jar > nohup_RS_noauth.out 2>&1 &