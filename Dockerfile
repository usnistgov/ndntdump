FROM golang:1.20-bullseye AS build
WORKDIR /app
COPY . .
RUN env GOBIN=/build go install ./cmd/ndntdump

FROM debian:bullseye-slim
COPY --from=build /build/* /
ENTRYPOINT ["/ndntdump"]
