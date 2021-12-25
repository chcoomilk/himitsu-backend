// This is missing lots of steps. More research needed
FROM rust:latest

WORKDIR /usr/src/himitsu

COPY . .

RUN cargo build

CMD cargo run
