package api

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/deepnavakoti/acra/internal/contract"
	"github.com/deepnavakoti/acra/internal/gateway"
	"github.com/deepnavakoti/acra/internal/identity"
	"github.com/deepnavakoti/acra/internal/incident"
	"github.com/deepnavakoti/acra/internal/pipeline"
)

// RegisterReadTools registers ACRA's read-only tools on gw. These are the only
// capabilities an automated reasoner gets.
func RegisterReadTools(gw *gateway.Gateway, p *pipeline.Service, trace func(id string) (any, error)) error {
	no := false
	idSchema := func(field string, max int) *contract.Schema {
		return &contract.Schema{Type: "object", Required: []string{field}, AdditionalProperties: &no,
			Properties: map[string]*contract.Schema{field: {Type: "string", MinLength: ptr(1), MaxLength: &max, Pattern: `^[A-Za-z0-9._:\-]+$`}}}
	}
	tools := []gateway.Tool{
		{
			Name: "incidents.list", Description: "List incidents, optionally filtered by status (open|investigating|resolved).",
			Role: identity.RoleReader,
			Args: &contract.Schema{Type: "object", AdditionalProperties: &no, Properties: map[string]*contract.Schema{
				"status": {Type: "string", Pattern: `^(open|investigating|resolved)$`}}},
			Handler: func(_ context.Context, a json.RawMessage) (any, error) {
				var in struct{ Status string }
				_ = json.Unmarshal(a, &in)
				return p.Incidents.List(incident.Status(in.Status))
			},
		},
		{
			Name: "incidents.get", Description: "Get one incident by id.", Role: identity.RoleReader, Args: idSchema("id", 64),
			Handler: func(_ context.Context, a json.RawMessage) (any, error) {
				var in struct{ ID string }
				if err := json.Unmarshal(a, &in); err != nil {
					return nil, err
				}
				return p.Incidents.Get(in.ID)
			},
		},
		{
			Name: "evaluations.recent", Description: "Recent contract evaluations for an agent.", Role: identity.RoleReader, Args: idSchema("agentId", 128),
			Handler: func(_ context.Context, a json.RawMessage) (any, error) {
				var in struct{ AgentID string }
				if err := json.Unmarshal(a, &in); err != nil {
					return nil, err
				}
				return p.Incidents.Evaluations(in.AgentID, 20)
			},
		},
		{
			Name: "contracts.get", Description: "Contracts registered for an agent.", Role: identity.RoleReader, Args: idSchema("agentId", 128),
			Handler: func(_ context.Context, a json.RawMessage) (any, error) {
				var in struct{ AgentID string }
				if err := json.Unmarshal(a, &in); err != nil {
					return nil, err
				}
				var out []*contract.Contract
				for _, c := range p.Contracts.All() {
					if c.AgentID == in.AgentID {
						out = append(out, c)
					}
				}
				return out, nil
			},
		},
	}
	if trace != nil {
		tools = append(tools, gateway.Tool{
			Name: "evidence.trace", Description: "Signed evidence trace by id.", Role: identity.RoleReader, Args: idSchema("id", 128),
			Handler: func(_ context.Context, a json.RawMessage) (any, error) {
				var in struct{ ID string }
				if err := json.Unmarshal(a, &in); err != nil {
					return nil, err
				}
				return trace(in.ID)
			},
		})
	}
	for _, t := range tools {
		if err := gw.Register(t); err != nil {
			return errors.New("register " + t.Name + ": " + err.Error())
		}
	}
	return nil
}

func ptr(i int) *int { return &i }
