package config

import (
	"fmt"
	"regexp"
	"strings"
)

// EvaluateScriptConditions checks if a node matches all conditions for a script.
// Returns true if all conditions match (or if no conditions are specified).
func EvaluateScriptConditions(node NodeConfig, conditions []ScriptCondition) (bool, error) {
	// No conditions = run on all nodes
	if len(conditions) == 0 {
		return true, nil
	}

	// All conditions must match (AND logic)
	for _, condition := range conditions {
		match, err := evaluateCondition(node, condition)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate condition on property '%s': %w", condition.Property, err)
		}
		if !match {
			return false, nil
		}
	}

	return true, nil
}

// evaluateCondition checks if a single condition matches the node.
func evaluateCondition(node NodeConfig, condition ScriptCondition) (bool, error) {
	// Get the property value from the node
	propertyValue, err := getNodeProperty(node, condition.Property)
	if err != nil {
		return false, err
	}

	var result bool

	// Evaluate based on operator
	switch strings.ToLower(condition.Operator) {
	case "=", "==", "equals":
		result = strings.EqualFold(propertyValue, condition.Value)

	case "!=", "notequals":
		result = !strings.EqualFold(propertyValue, condition.Value)

	case "regex", "matches":
		// Case-insensitive regex match
		pattern := "(?i)" + condition.Value
		matched, err := regexp.MatchString(pattern, propertyValue)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern '%s': %w", condition.Value, err)
		}
		result = matched

	case "!regex", "notmatches":
		// Case-insensitive regex non-match
		pattern := "(?i)" + condition.Value
		matched, err := regexp.MatchString(pattern, propertyValue)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern '%s': %w", condition.Value, err)
		}
		result = !matched

	default:
		return false, fmt.Errorf("unsupported operator '%s' (supported: =, !=, regex, !regex)", condition.Operator)
	}

	// Apply negation if requested
	if condition.Negate {
		result = !result
	}

	return result, nil
}

// getNodeProperty retrieves a property value from a node by name.
func getNodeProperty(node NodeConfig, property string) (string, error) {
	switch strings.ToLower(property) {
	case "sshfqdnorip", "hostname": // hostname kept for backwards compatibility
		return node.SSHFQDNorIP, nil
	case "username":
		return node.Username, nil
	case "role":
		return node.Role, nil
	case "newhostname":
		return node.NewHostname, nil
	case "advertiseaddr":
		return node.AdvertiseAddr, nil
	case "sshport":
		return fmt.Sprintf("%d", node.SSHPort), nil
	case "storageenabled":
		if node.StorageEnabled {
			return "true", nil
		}
		return "false", nil
	case "rebootoncompletion":
		if node.RebootOnCompletion {
			return "true", nil
		}
		return "false", nil
	case "scriptsenabled":
		if node.ScriptsEnabled {
			return "true", nil
		}
		return "false", nil
	case "usesshautomatickeypair":
		if node.UseSSHAutomaticKeyPair {
			return "true", nil
		}
		return "false", nil
	case "enabled":
		if node.Enabled == nil || *node.Enabled {
			return "true", nil
		}
		return "false", nil
	default:
		// Check custom labels
		if strings.HasPrefix(strings.ToLower(property), "label.") {
			labelKey := property[6:] // Remove "label." prefix
			if value, exists := node.Labels[labelKey]; exists {
				return value, nil
			}
			return "", nil // Label doesn't exist, return empty string
		}
		return "", fmt.Errorf("unknown property '%s'", property)
	}
}

