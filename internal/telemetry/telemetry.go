// Package telemetry emits an OpenTelemetry span per gate decision. Each span
// carries TWO distinct id sets (docs/04-api-and-schemas.md §4): operational
// correlation ids and ACRA's own acra.* proof attributes. GenAI semantic
// conventions are still emerging, so ACRA namespaces its proof attrs under acra.*.
//
// Export is best-effort: with OTEL_EXPORTER_OTLP_ENDPOINT set, spans go to an
// OTLP collector; otherwise they are no-ops. Telemetry never breaks the app.
package telemetry

import (
	"context"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/deepnavakoti/acra/internal/model"
)

var tracer = otel.Tracer("acra")

// Init sets up OTLP export if OTEL_EXPORTER_OTLP_ENDPOINT is set. Returns a
// shutdown func. Any failure degrades to no-op spans — never fatal.
func Init(ctx context.Context) func(context.Context) error {
	noop := func(context.Context) error { return nil }
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		return noop
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	exp, err := otlptracegrpc.New(ctx, otlptracegrpc.WithInsecure())
	if err != nil {
		return noop
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", "acra-apiserver"))),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown
}

// RecordGate emits one span for a gate decision, with both id sets. Operational
// ids come from the ticket; ids that are unknown are omitted, never invented.
func RecordGate(ctx context.Context, t model.Ticket) {
	_, span := tracer.Start(ctx, "acra.gate.evaluate")
	defer span.End()
	attrs := []attribute.KeyValue{
		// operational correlation ids
		attribute.String("task.id", t.ID),
		attribute.String("caller.spiffe", "spiffe://acra/"+t.Agent),
		// ACRA proof attributes
		attribute.String("acra.detector", t.Detector),
		attribute.String("acra.verdict", string(model.Hold)),
		attribute.String("acra.model.version", t.ModelPin),
		attribute.String("acra.response.fingerprint", t.Bundle),
	}
	if t.Epoch > 0 {
		attrs = append(attrs, attribute.Int("epoch", t.Epoch))
	}
	if t.Attempt > 0 {
		attrs = append(attrs, attribute.Int("attempt", t.Attempt))
	}
	if t.Step > 0 {
		attrs = append(attrs, attribute.Int("step", t.Step))
	}
	span.SetAttributes(attrs...)
}
