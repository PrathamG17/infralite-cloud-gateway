FROM ubuntu:24.04 AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cmake -S . -B /build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_DESKTOP_APP=OFF \
    -DBUILD_TESTING=OFF \
    && cmake --build /build --target infralite-server --parallel

FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home infralite \
    && mkdir -p /app/data /app/logs /app/certs \
    && chown -R infralite:infralite /app

WORKDIR /app
COPY --from=build /build/infralite-server /app/infralite-server
COPY config /app/config
COPY static /app/static

USER infralite
VOLUME ["/app/data", "/app/certs"]
EXPOSE 8080
ENTRYPOINT ["/app/infralite-server"]
CMD ["--https"]