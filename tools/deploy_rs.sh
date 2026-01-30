export SPRING_PROFILES_ACTIVE=dev
nohup java -jar resource_server/target/resource_server-0.0.1-SNAPSHOT.jar > nohup_RS.out 2>&1 &