FROM debian:bullseye-slim

RUN apt update && apt install -y gcc iproute2

COPY syn_flood.c /syn_flood.c

RUN gcc /syn_flood.c -o /syn_flood -pthread

CMD ["/syn_flood"]
