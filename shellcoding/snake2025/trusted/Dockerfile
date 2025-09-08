FROM archlinux@sha256:97c56e9c792dc50df96c77187255a752f479698c9beb4aa9caeb9fe4639a7590 AS chroot

RUN useradd -m user
USER user

WORKDIR /home/user/

COPY --chown=user:user trusted trusted
COPY --chown=user:user wrapper wrapper
COPY --chown=user:user default_progs/ default_progs/
COPY --chown=user:user public.pem public.pem

RUN chmod +x trusted && chmod +x wrapper && chmod -R 540 default_progs/ && chmod 440 public.pem

FROM ghcr.io/madrhacks/jail:latest

COPY --from=chroot / /srv

ENV FLAG_PATH=/home/user/flag
ENV EXEC=/home/user/trusted
ENV CWD=/home/user
ENV TMP_SIZE=1048576
ENV TIMEOUT=300
