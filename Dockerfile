FROM golang:1.26-alpine3.23 AS build
WORKDIR /app
COPY . .
RUN env CGO_ENABLED=0 GOBIN=/build go install ./cmd/ndntdump

FROM scratch
COPY --from=build /build/* /
ENTRYPOINT ["/ndntdump"]
