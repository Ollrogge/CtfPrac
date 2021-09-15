FROM python:latest

RUN apt-get update && apt-get install -y socat
RUN useradd -m ctf && ulimit -c 0

WORKDIR /home/ctf
COPY . ./
RUN chown root:root . && chmod a+w ./sandbox && chmod +s ./sandbox/lottery

USER ctf
CMD socat TCP4-LISTEN:1024,fork,reuseaddr,max-children=4 EXEC:./server.py
