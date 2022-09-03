FROM rust:latest

WORKDIR /usr/src/himitsu

COPY . .

RUN cargo install diesel_cli && diesel run migration
RUN cargo build

CMD cargo run
