FROM golang:1.21-bookworm AS build
WORKDIR /app
COPY . .
RUN env GOBIN=/build go install ./cmd/ndntdump

FROM debian:bookworm-slim
COPY --from=build /build/* /
ENTRYPOINT ["/ndntdump"]
