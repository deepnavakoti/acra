# ACRA image — builds the apiserver + workload, bakes in the console.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/apiserver  ./cmd/apiserver \
 && CGO_ENABLED=0 go build -trimpath -o /out/workload   ./cmd/workload \
 && CGO_ENABLED=0 go build -trimpath -o /out/controller ./cmd/controller

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/apiserver  /app/apiserver
COPY --from=build /out/workload   /app/workload
COPY --from=build /out/controller /app/controller
COPY console /app/console
EXPOSE 8080
ENTRYPOINT ["/app/apiserver", "-addr", ":8080", "-console", "/app/console/index.html", "-db", "/tmp/acra-evidence.db"]
