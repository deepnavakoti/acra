# ACRA image — apiserver, gate, controller and workload binaries + the console.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/apiserver  ./cmd/apiserver \
 && CGO_ENABLED=0 go build -trimpath -o /out/workload   ./cmd/workload \
 && CGO_ENABLED=0 go build -trimpath -o /out/controller ./cmd/controller \
 && CGO_ENABLED=0 go build -trimpath -o /out/gate       ./cmd/gate

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/apiserver  /app/apiserver
COPY --from=build /out/workload   /app/workload
COPY --from=build /out/controller /app/controller
COPY --from=build /out/gate       /app/gate
COPY console /app/console
EXPOSE 8080
# Default = local demo. Production (Helm) overrides the command per component and
# passes -key-file, -demo=false and the persistent store paths.
ENTRYPOINT ["/app/apiserver"]
CMD ["-addr", ":8080", "-console", "/app/console/index.html", "-db", "/tmp/acra-evidence.db", "-incident-db", "/tmp/acra-incidents.db"]
