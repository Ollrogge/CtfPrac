FROM ubuntu:24.04@sha256:77d57fd89366f7d16615794a5b53e124d742404e20f035c22032233f1826bd6a AS base
WORKDIR /app
COPY chall run
RUN  echo "FLAG{*** REDACTED ***}" > /flag.txt
RUN  mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=180 JAIL_CPU=100 JAIL_MEM=10M
