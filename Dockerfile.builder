FROM rust:slim-bookworm
RUN apt-get update && apt-get install -y build-essential pkg-config libssl-dev clang libclang-dev cmake
WORKDIR /work
