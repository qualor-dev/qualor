#!/bin/sh
# Removes what the deploy scripts (plan 1G) left behind after a failed or cancelled CI run: the
# containers and volumes labelled qualor.deploy (scanner and Node containers, checkout volumes,
# the pnpm store), and the throwaway compose stacks, whose project names all start with
# "qualor-" (qualor-smoke-*, qualor-dogfood-*, qualor-exit-test-*, qualor-screenshots-*).
# Nothing else on the Docker host is touched: on a shared or self-hosted runner, other compose
# projects, and a real "qualor" stack, stay as they are.
set -u

docker ps -aq --filter label=qualor.deploy | xargs -r docker rm -f

projects=$({
  docker ps -a --format '{{.Label "com.docker.compose.project"}}'
  docker network ls --format '{{.Label "com.docker.compose.project"}}'
  docker volume ls --format '{{.Label "com.docker.compose.project"}}'
} | grep '^qualor-' | sort -u)

for project in $projects; do
  filter="label=com.docker.compose.project=$project"
  docker ps -aq --filter "$filter" | xargs -r docker rm -f
  docker network ls -q --filter "$filter" | xargs -r docker network rm
  docker volume ls -q --filter "$filter" | xargs -r docker volume rm -f
done

docker volume ls -q --filter label=qualor.deploy | xargs -r docker volume rm -f
exit 0
