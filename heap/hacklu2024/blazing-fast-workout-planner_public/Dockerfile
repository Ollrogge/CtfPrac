# To run this challenge locally,
#   (1) build the Docker container
#         docker build -t hacklu2024/blazing-fast-workout-planner .
#   (2) run the Docker container
#         docker run --cap-add SYS_ADMIN --security-opt apparmor=unconfined --rm -p 127.0.0.1:1024:1024 -ti hacklu2024/blazing-fast-workout-planner
# and connect to localhost:1024

FROM rust:latest AS builder

RUN mkdir /src

COPY ./ /src

RUN cd /src && cargo build

FROM ubuntu@sha256:d4f6f70979d0758d7a6f81e34a61195677f4f4fa576eaf808b79f17499fd93d1

RUN useradd --no-create-home --shell /bin/bash ctf

COPY ynetd /sbin/ynetd

COPY flag.txt /flag.txt

COPY --from=builder /src/target/debug/blazing_fast_workout_planner /chall

RUN chown -R root:root /sbin && \
  chown root:root /flag.txt && \
  chown root:root /chall && \
  chmod 744 /flag.txt && \
  chmod 755 /chall

EXPOSE 1234
SHELL ["/bin/sh", "-c"]
CMD ynetd -lt 15 -t 15 -lm 268435456 -lpid 128 -sh n -d / /chall
