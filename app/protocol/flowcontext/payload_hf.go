package flowcontext

// IsPayloadHfActive returns whether anti-fraud payload HF rules are active at the current virtual DAA score.
func (f *FlowContext) IsPayloadHfActive() bool {
	virtualDAAScore, err := f.Domain().Consensus().GetVirtualDAAScore()
	if err != nil {
		return false
	}
	return virtualDAAScore >= f.Config().NetParams().PayloadHfActivationDAAScore
}

// IsAntiFraudRuntimeEnabled returns whether antifraud runtime checks are currently enabled.
func (f *FlowContext) IsAntiFraudRuntimeEnabled() bool {
	if f.ConnectionManager() == nil {
		return false
	}
	return f.ConnectionManager().IsAntiFraudRuntimeEnabled()
}
