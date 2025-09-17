package policy

import (
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Engine manages firewall policies and enforcement actions
type Engine struct {
	logger   *logrus.Logger
	rules    map[string]*Rule
	actions  map[string]*Action
	rulesMux sync.RWMutex
}

// Rule represents a firewall rule
type Rule struct {
	ID          string
	Name        string
	Description string
	Enabled     bool
	Priority    int
	Conditions  []Condition
	Actions     []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Condition represents a rule condition
type Condition struct {
	Field    string      // "threat_score", "source_ip", "dest_port", etc.
	Operator string      // "gt", "lt", "eq", "in", "contains"
	Value    interface{} // threshold value or list
}

// Action represents an enforcement action
type Action struct {
	ID          string
	Type        string // "block", "quarantine", "alert", "rate_limit", "redirect"
	Parameters  map[string]interface{}
	Description string
}

// DecisionRequest represents a policy decision request
type DecisionRequest struct {
	FlowID         string
	SourceIP       string
	DestIP         string
	DestPort       uint16
	Protocol       string
	ThreatScore    float64
	ThreatCategory string
	UserID         string
	DeviceID       string
	Metadata       map[string]interface{}
}

// DecisionResponse represents a policy decision response
type DecisionResponse struct {
	Allow       bool
	Actions     []string
	Reason      string
	RuleID      string
	Confidence  float64
	ProcessedAt time.Time
}

// NewEngine creates a new policy engine
func NewEngine(logger *logrus.Logger) *Engine {
	engine := &Engine{
		logger:  logger,
		rules:   make(map[string]*Rule),
		actions: make(map[string]*Action),
	}

	// Initialize default rules and actions
	engine.initializeDefaults()

	return engine
}

// initializeDefaults sets up default rules and actions
func (e *Engine) initializeDefaults() {
	// Default actions
	e.actions["block"] = &Action{
		ID:          "block",
		Type:        "block",
		Description: "Block the connection",
		Parameters:  map[string]interface{}{"duration": "permanent"},
	}

	e.actions["quarantine"] = &Action{
		ID:          "quarantine",
		Type:        "quarantine",
		Description: "Quarantine the flow for analysis",
		Parameters:  map[string]interface{}{"sandbox_time": 300},
	}

	e.actions["alert"] = &Action{
		ID:          "alert",
		Type:        "alert",
		Description: "Generate security alert",
		Parameters:  map[string]interface{}{"severity": "medium"},
	}

	e.actions["rate_limit"] = &Action{
		ID:          "rate_limit",
		Type:        "rate_limit",
		Description: "Apply rate limiting",
		Parameters:  map[string]interface{}{"requests_per_second": 10},
	}

	// Default rules
	highThreatRule := &Rule{
		ID:          "high_threat_block",
		Name:        "Block High Threat Flows",
		Description: "Block flows with high threat scores",
		Enabled:     true,
		Priority:    1,
		Conditions: []Condition{
			{Field: "threat_score", Operator: "gt", Value: 0.8},
		},
		Actions:   []string{"block", "alert"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mediumThreatRule := &Rule{
		ID:          "medium_threat_quarantine",
		Name:        "Quarantine Medium Threat Flows",
		Description: "Quarantine flows with medium threat scores",
		Enabled:     true,
		Priority:    2,
		Conditions: []Condition{
			{Field: "threat_score", Operator: "gt", Value: 0.5},
			{Field: "threat_score", Operator: "lt", Value: 0.8},
		},
		Actions:   []string{"quarantine", "alert"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	e.rules[highThreatRule.ID] = highThreatRule
	e.rules[mediumThreatRule.ID] = mediumThreatRule

	e.logger.WithField("rules_loaded", len(e.rules)).Info("Default policy rules initialized")
}

// Evaluate evaluates a decision request against all rules
func (e *Engine) Evaluate(request *DecisionRequest) *DecisionResponse {
	e.rulesMux.RLock()
	defer e.rulesMux.RUnlock()

	// Default response - allow
	response := &DecisionResponse{
		Allow:       true,
		Actions:     []string{},
		Reason:      "No matching rules",
		Confidence:  1.0,
		ProcessedAt: time.Now(),
	}

	// Evaluate rules in priority order
	for _, rule := range e.getSortedRules() {
		if !rule.Enabled {
			continue
		}

		if e.evaluateRule(rule, request) {
			// Rule matched - apply actions
			response.Allow = e.shouldAllow(rule.Actions)
			response.Actions = rule.Actions
			response.RuleID = rule.ID
			response.Reason = fmt.Sprintf("Matched rule: %s", rule.Name)
			response.Confidence = 0.95

			e.logger.WithFields(logrus.Fields{
				"rule_id":      rule.ID,
				"flow_id":      request.FlowID,
				"threat_score": request.ThreatScore,
				"actions":      response.Actions,
			}).Info("Policy rule matched")

			break // First matching rule wins
		}
	}

	return response
}

// evaluateRule checks if a rule matches the request
func (e *Engine) evaluateRule(rule *Rule, request *DecisionRequest) bool {
	for _, condition := range rule.Conditions {
		if !e.evaluateCondition(condition, request) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition
func (e *Engine) evaluateCondition(condition Condition, request *DecisionRequest) bool {
	var fieldValue interface{}

	// Extract field value from request
	switch condition.Field {
	case "threat_score":
		fieldValue = request.ThreatScore
	case "source_ip":
		fieldValue = request.SourceIP
	case "dest_port":
		fieldValue = request.DestPort
	case "protocol":
		fieldValue = request.Protocol
	case "threat_category":
		fieldValue = request.ThreatCategory
	default:
		if val, exists := request.Metadata[condition.Field]; exists {
			fieldValue = val
		} else {
			return false
		}
	}

	// Evaluate condition based on operator
	switch condition.Operator {
	case "gt":
		if fv, ok := fieldValue.(float64); ok {
			if cv, ok := condition.Value.(float64); ok {
				return fv > cv
			}
		}
	case "lt":
		if fv, ok := fieldValue.(float64); ok {
			if cv, ok := condition.Value.(float64); ok {
				return fv < cv
			}
		}
	case "eq":
		return fieldValue == condition.Value
	case "contains":
		if fv, ok := fieldValue.(string); ok {
			if cv, ok := condition.Value.(string); ok {
				return fv == cv // Simplified contains
			}
		}
	}

	return false
}

// shouldAllow determines if actions include blocking
func (e *Engine) shouldAllow(actions []string) bool {
	for _, action := range actions {
		if action == "block" {
			return false
		}
	}
	return true
}

// getSortedRules returns rules sorted by priority
func (e *Engine) getSortedRules() []*Rule {
	rules := make([]*Rule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}

	// Simple bubble sort by priority (higher priority first)
	for i := 0; i < len(rules)-1; i++ {
		for j := 0; j < len(rules)-i-1; j++ {
			if rules[j].Priority > rules[j+1].Priority {
				rules[j], rules[j+1] = rules[j+1], rules[j]
			}
		}
	}

	return rules
}

// AddRule adds a new rule to the engine
func (e *Engine) AddRule(rule *Rule) error {
	e.rulesMux.Lock()
	defer e.rulesMux.Unlock()

	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	e.rules[rule.ID] = rule

	e.logger.WithField("rule_id", rule.ID).Info("Rule added")
	return nil
}

// UpdateRule updates an existing rule
func (e *Engine) UpdateRule(ruleID string, rule *Rule) error {
	e.rulesMux.Lock()
	defer e.rulesMux.Unlock()

	if _, exists := e.rules[ruleID]; !exists {
		return fmt.Errorf("rule %s not found", ruleID)
	}

	rule.UpdatedAt = time.Now()
	e.rules[ruleID] = rule

	e.logger.WithField("rule_id", ruleID).Info("Rule updated")
	return nil
}

// DeleteRule removes a rule
func (e *Engine) DeleteRule(ruleID string) error {
	e.rulesMux.Lock()
	defer e.rulesMux.Unlock()

	if _, exists := e.rules[ruleID]; !exists {
		return fmt.Errorf("rule %s not found", ruleID)
	}

	delete(e.rules, ruleID)
	e.logger.WithField("rule_id", ruleID).Info("Rule deleted")
	return nil
}

// GetRules returns all rules
func (e *Engine) GetRules() map[string]*Rule {
	e.rulesMux.RLock()
	defer e.rulesMux.RUnlock()

	// Return copy to prevent modification
	rules := make(map[string]*Rule)
	for k, v := range e.rules {
		rules[k] = v
	}
	return rules
}
