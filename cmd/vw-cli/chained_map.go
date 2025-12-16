package main

type ChainedMap map[string]string

func (mvc *ChainedMap) HasChained(keys ...string) bool {
	for _, key := range keys {
		if !mvc.Has(key) {
			return false
		}
	}
	return true
}

func (mvc *ChainedMap) Has(key string) bool {
	_, ok := (*mvc)[key]
	if ok {
		return true
	}
	return false
}
