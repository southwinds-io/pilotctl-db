# Deploy Pilot Control Database Schemas on a PostgreSQL container

docker rm -f pilotctl-db > /dev/null

echo "checking port 5432 is available for Pilot Control database process"
lsof -i:5432 | grep LISTEN
RESULT=$?
if [ $RESULT -eq 0 ]; then
  echo port 5432 is in use, cannot continue: ensure there is no process using 5432/tcp port
  exit 1
fi

echo "creating Interlink database container"
docker run --name pilotctl-db -it -d -p 5432:5432 -e POSTGRES_PASSWORD=p0stgr3s "postgres"

echo "configuring DbMan for managing the pilotctl database"
dbman config use -n pilotctl
dbman config set Repo.URI .
# for online use can set the URI to the http location of this project as shown below
#dbman config set Repo.URI https://raw.githubusercontent.com/southwinds-io/pilotctl-db/master
dbman config set AppVersion 1.0.0
dbman config set Db.Name pilotctl
dbman config set Db.Host localhost
dbman config set Db.Port 5432
dbman config set Db.Username pilotctl
dbman config set Db.Password p1l0tctl
dbman config set Db.AdminUsername postgres
dbman config set Db.AdminPassword p0stgr3s

echo "waiting for database server to start"
sleep 2

echo "creating database"
dbman db create

echo "deploying database schemas"
dbman db deploy

