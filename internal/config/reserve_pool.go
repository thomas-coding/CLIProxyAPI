package config

// ReservePoolConfig controls the sidecar reserve Codex auth pool.
// These settings do not alter the production auth-manager flow directly.
type ReservePoolConfig struct {
	// ProductionAvailableThreshold starts one replenish round when the current
	// production Codex available count falls below this number.
	ProductionAvailableThreshold int `yaml:"production-available-threshold" json:"production-available-threshold"`

	// ReplenishBatchSize limits how many reserve auths can be promoted in one round.
	ReplenishBatchSize int `yaml:"replenish-batch-size" json:"replenish-batch-size"`

	// ValidateUsageBeforePromotion requires a Codex usage probe to return HTTP 200
	// before the reserve auth is promoted into the production pool.
	ValidateUsageBeforePromotion bool `yaml:"validate-usage-before-promotion" json:"validate-usage-before-promotion"`
}
