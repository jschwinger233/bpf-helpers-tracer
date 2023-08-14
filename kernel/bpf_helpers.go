package kernel

func GetHelpersFromBpfPrograms() (helpers []string, err error) {
	return []string{"bpf_skb_pull_data"}, nil
}
